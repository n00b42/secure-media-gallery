/**
 * E2E Encryption Manager for Secure Media Gallery
 *
 * All encryption/decryption happens here in the browser.
 * The server receives only ciphertexts, public keys and a one-way auth key —
 * never plaintext files, private keys or the password.
 *
 * Account keys (one password, two independent keys)
 * ─────────────────────────────────────────────────
 *   master   = Argon2id(NFC(password), "secure-media-gallery|v3|" + username, 64 MiB, 3 passes)
 *              (hash-wasm, src/static/vendor/hash-wasm; memory-hard, so guessing on GPUs is costly)
 *   authKey  = HKDF-SHA256(master, info "auth")  → sent to the server at login (it stores a hash)
 *   wrapKey  = HKDF-SHA256(master, info "wrap")  → never leaves the browser; encrypts the private key
 *   (Mirrored in src/security.py → derive_account_keys. Keep both in sync.)
 *
 * Key hierarchy
 * ─────────────
 *   RSA-OAEP 4096 key pair  (one per user)
 *     └─ private key  →  AES-GCM wrapped with wrapKey; the ciphertext is stored on the server
 *     └─ public key   →  SPKI base64, stored on the server; fingerprint shown on /keys
 *
 *   AES-GCM 256 file key  (one per uploaded file)
 *     └─ encrypts the file blob in the browser before upload
 *     └─ RSA-OAEP encrypted for every album member, stored on the server
 */

// CSRF: every same-origin POST/PUT/DELETE sent with fetch() carries the session's
// token (from <meta name="csrf-token">) in the X-CSRFToken header.
(() => {
  if (typeof window === 'undefined' || !window.fetch) return; // e.g. loaded by a test in Node
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const request = input instanceof Request ? input : null;
    const method = String(init.method || request?.method || 'GET').toUpperCase();
    const url = new URL(request ? request.url : String(input), location.href);
    const token = document.querySelector('meta[name="csrf-token"]')?.content;
    if (token && url.origin === location.origin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const headers = new Headers(init.headers || request?.headers);
      if (!headers.has('X-CSRFToken')) headers.set('X-CSRFToken', token);
      init = { ...init, headers };
    }
    return originalFetch(input, init);
  };
})();

const E2E_ARGON2 = { memorySize: 64 * 1024, iterations: 3, parallelism: 1 }; // KiB; = security.py
const E2E_KDF_SALT_PREFIX = 'secure-media-gallery|v3|';
const E2E_HKDF_SALT = 'secure-media-gallery|hkdf|v2';
const E2E_MIN_PASSWORD_LENGTH = 8;
const E2E_SESSION_WRAP_KEY = 'e2e_wrap_key';

class E2EEncryptionManager {
  constructor() {
    // mediaId → Promise<{ rawKeyB64, meta, filename }>; lives as long as the page
    this._mediaContexts = new Map();
    this.aesAlgo = { name: 'AES-GCM', length: 256 };
    this.rsaAlgo = {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    };
  }

  // ─── Account key derivation ────────────────────────────────────────────────

  normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
  }

  /**
   * Derive { authKeyHex, wrapKeyB64 } from username + password.
   * authKeyHex is what the server sees; wrapKeyB64 must stay in the browser.
   */
  async deriveAccountKeys(username, password) {
    const enc = new TextEncoder();
    const salt = enc.encode(E2E_KDF_SALT_PREFIX + this.normalizeUsername(username));
    if (typeof hashwasm === 'undefined' || !hashwasm.argon2id) {
      throw new Error('Argon2 library not loaded');
    }
    const master = await hashwasm.argon2id({
      password: enc.encode(String(password).normalize('NFC')),
      salt,
      ...E2E_ARGON2,
      hashLength: 32,
      outputType: 'binary',
    });
    const hkdfKey = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
    const hkdf = (info) => crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(E2E_HKDF_SALT), info: enc.encode(info) },
      hkdfKey, 256,
    );
    const [authBits, wrapBits] = await Promise.all([hkdf('auth'), hkdf('wrap')]);
    return { authKeyHex: this._buf2hex(authBits), wrapKeyB64: this._buf2b64(wrapBits) };
  }

  // Session cache of the wrap key, so the password is not asked on every page.
  // (Replaces the old plaintext password in sessionStorage.)
  saveSessionWrapKey(wrapKeyB64) { sessionStorage.setItem(E2E_SESSION_WRAP_KEY, wrapKeyB64); }
  loadSessionWrapKey() { return sessionStorage.getItem(E2E_SESSION_WRAP_KEY); }
  clearSessionSecrets() { sessionStorage.removeItem(E2E_SESSION_WRAP_KEY); }

  // ─── RSA key pair ───────────────────────────────────────────────────────────

  async generateKeyPair() {
    return crypto.subtle.generateKey(this.rsaAlgo, true, ['encrypt', 'decrypt']);
  }

  async exportPublicKey(publicKey) {
    const buf = await crypto.subtle.exportKey('spki', publicKey);
    return this._buf2b64(buf);
  }

  async importPublicKey(b64) {
    return crypto.subtle.importKey('spki', this._b642buf(b64), this.rsaAlgo, true, ['encrypt']);
  }

  /** Import a private key as NON-extractable: page scripts can use it, not export it. */
  async _importPrivatePkcs8(pkcs8) {
    return crypto.subtle.importKey('pkcs8', pkcs8, this.rsaAlgo, false, ['decrypt']);
  }

  /**
   * Human-comparable fingerprint of a public key: SHA-256 over the SPKI bytes,
   * as 16 groups of 4 hex digits. Compare it out-of-band to detect key substitution.
   */
  async fingerprint(publicKeyB64) {
    const digest = await crypto.subtle.digest('SHA-256', this._b642buf(publicKeyB64));
    return this._buf2hex(digest).toUpperCase().match(/.{4}/g).join(' ');
  }

  // ─── AES file key ────────────────────────────────────────────────────────────

  async generateFileKey() {
    return crypto.subtle.generateKey(this.aesAlgo, true, ['encrypt', 'decrypt']);
  }

  async exportRawKey(key) {
    const buf = await crypto.subtle.exportKey('raw', key);
    return this._buf2b64(buf);
  }

  async importRawKey(b64) {
    return crypto.subtle.importKey('raw', this._b642buf(b64), this.aesAlgo, true, ['encrypt', 'decrypt']);
  }

  // ─── File encrypt / decrypt ──────────────────────────────────────────────────

  /**
   * Encrypt an ArrayBuffer.
   * Returns { encryptedBytes: Uint8Array, ivB64: string }
   */
  async encryptFile(fileBuffer, fileKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, fileBuffer);
    return { encryptedBytes: new Uint8Array(encrypted), ivB64: this._buf2b64(iv) };
  }

  async encryptStringWithRawKey(value, rawKeyB64) {
    const fileKey = await this.importRawKey(rawKeyB64);
    const encoded = new TextEncoder().encode(value);
    const { encryptedBytes, ivB64 } = await this.encryptFile(encoded.buffer, fileKey);
    return JSON.stringify({
      version: 1,
      iv_b64: ivB64,
      data_b64: this._buf2b64(encryptedBytes),
    });
  }

  async decryptStringWithRawKey(encryptedJson, rawKeyB64) {
    const payload = JSON.parse(encryptedJson);
    if (!payload || payload.version !== 1 || !payload.iv_b64 || !payload.data_b64) {
      throw new Error('Invalid encrypted string payload');
    }

    const fileKey = await this.importRawKey(rawKeyB64);
    const decrypted = await this.decryptFile(this._b642buf(payload.data_b64), fileKey, payload.iv_b64);
    return new TextDecoder().decode(decrypted);
  }

  /**
   * Decrypt an ArrayBuffer given the AES key and IV (base64).
   */
  async decryptFile(encryptedBuffer, fileKey, ivB64) {
    const iv = this._b642buf(ivB64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, fileKey, encryptedBuffer);
  }

  // ─── RSA key wrapping for file keys ─────────────────────────────────────────

  async encryptKeyForRecipient(rawKeyB64, recipientPublicKey) {
    const keyBuf = this._b642buf(rawKeyB64);
    const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, keyBuf);
    return this._buf2b64(encrypted);
  }

  async decryptKeyWithPrivateKey(encryptedKeyB64, privateKey) {
    const buf = this._b642buf(encryptedKeyB64);
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buf);
    return this._buf2b64(raw);
  }

  async fetchRawFileKey(mediaId, privateKey) {
    const metaRes = await fetch(`/api/media/${mediaId}/key`);
    if (!metaRes.ok) throw new Error(`Key fetch failed: ${metaRes.status}`);
    const meta = await metaRes.json();
    const rawKeyB64 = await this.decryptKeyWithPrivateKey(meta.encrypted_key, privateKey);
    return { rawKeyB64, meta };
  }

  /**
   * File key + decrypted original file name for a media item, fetched and
   * RSA-decrypted once per page (thumbnail, poster and lightbox share it).
   */
  getMediaContext(mediaId, privateKey) {
    const id = String(mediaId);
    if (!this._mediaContexts.has(id)) {
      const promise = (async () => {
        const { rawKeyB64, meta } = await this.fetchRawFileKey(mediaId, privateKey);
        let filename = '';
        try {
          filename = await this.decryptStringWithRawKey(meta.encrypted_filename, rawKeyB64);
        } catch {
          filename = '';
        }
        return { rawKeyB64, meta, filename };
      })();
      promise.catch(() => this._mediaContexts.delete(id)); // allow retry after errors
      this._mediaContexts.set(id, promise);
    }
    return this._mediaContexts.get(id);
  }

  // ─── Private key wrapping ───────────────────────────────────────────────────

  async _wrapKeyFromB64(wrapKeyB64) {
    return crypto.subtle.importKey('raw', this._b642buf(wrapKeyB64), this.aesAlgo, false, ['encrypt', 'decrypt']);
  }

  /** Wrap PKCS#8 bytes with the wrap key → v2 JSON {v, iv, data}. */
  async wrapPkcs8(pkcs8, wrapKeyB64) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this._wrapKeyFromB64(wrapKeyB64);
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pkcs8);
    return JSON.stringify({ v: 2, iv: this._buf2b64(iv), data: this._buf2b64(wrapped) });
  }

  /** Decrypt a v2 backup to raw PKCS#8 bytes (password change). Throws on wrong key. */
  async unwrapPkcs8(wrappedJson, wrapKeyB64) {
    const { v, iv, data } = JSON.parse(wrappedJson);
    if (v !== 2) throw new Error('Not a v2 wrapped key');
    const key = await this._wrapKeyFromB64(wrapKeyB64);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: this._b642buf(iv) }, key, this._b642buf(data));
  }

  /** Unwrap a v2 backup into a non-extractable private key. Throws on wrong key. */
  async unwrapPrivateKey(wrappedJson, wrapKeyB64) {
    return this._importPrivatePkcs8(await this.unwrapPkcs8(wrappedJson, wrapKeyB64));
  }

  // ─── Key pair creation ──────────────────────────────────────────────────────

  /** Generate a key pair and wrap the private key. Nothing is uploaded. */
  async createWrappedKeyPair(wrapKeyB64) {
    const keyPair = await this.generateKeyPair();
    const publicKeyB64 = await this.exportPublicKey(keyPair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const wrappedPrivateKey = await this.wrapPkcs8(pkcs8, wrapKeyB64);
    const privateKey = await this._importPrivatePkcs8(pkcs8);
    return { publicKeyB64, wrappedPrivateKey, privateKey };
  }

  /**
   * Generate a NEW key pair and replace the one on the server.
   * WARNING: files encrypted for the previous key become unreadable for this user.
   */
  async setupKeys(wrapKeyB64) {
    const { publicKeyB64, wrappedPrivateKey, privateKey } = await this.createWrappedKeyPair(wrapKeyB64);
    const res = await fetch('/api/keys/me', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ public_key: publicKeyB64, wrapped_private_key: wrappedPrivateKey }),
    });
    if (!res.ok) throw new Error(`Key upload failed: ${res.status}`);
    return privateKey;
  }

  async saveWrappedPrivateKeyToServer(wrappedJson) {
    const res = await fetch('/api/keys/me/private', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ wrapped_private_key: wrappedJson }),
    });
    if (!res.ok) throw new Error(`Server backup failed: ${res.status}`);
  }

  async loadWrappedPrivateKeyFromServer() {
    const res = await fetch('/api/keys/me/private');
    if (!res.ok) throw new Error(`Server backup fetch failed: ${res.status}`);
    const data = await res.json();
    return data.wrapped_private_key || null;
  }

  // ─── View / download (chunked format, see chunked-file.js) ─────────────────

  /** Everything needed to decrypt a media item: key, chunk format, sizes, name. */
  async mediaFileInfo(mediaId, privateKey) {
    const { rawKeyB64, meta, filename } = await this.getMediaContext(mediaId, privateKey);
    return {
      mediaId,
      rawKeyB64,
      nonceB64: meta.nonce_b64,
      chunkSize: meta.chunk_size,
      cipherSize: meta.file_size,
      plainSize: SMGChunked.layout(meta.file_size, meta.chunk_size).plainSize,
      fileType: meta.file_type,
      filename: filename || `file-${mediaId}`,
      mime: this._guessMime(filename),
    };
  }

  async _decryptInfo(info) {
    return {
      key: await crypto.subtle.importKey('raw', this._b642buf(info.rawKeyB64), this.aesAlgo, false, ['decrypt']),
      nonce: new Uint8Array(this._b642buf(info.nonceB64)),
      chunkSize: info.chunkSize,
      cipherSize: info.cipherSize,
      fetchCipher: SMGChunked.mediaFetcher(info.mediaId),
    };
  }

  /**
   * Fetch an encrypted file, decrypt it in memory, and return { url, filename }.
   * For images and small files; large videos and downloads go through e2eStream.
   * The caller must revoke the object URL when done.
   */
  async fetchAndDecrypt(mediaId, privateKey) {
    const info = await this.mediaFileInfo(mediaId, privateKey);
    const blob = await SMGChunked.decryptToBlob(await this._decryptInfo(info), info.mime);
    return { url: URL.createObjectURL(blob), filename: info.filename };
  }

  /**
   * Decrypt an upload-time video poster (encrypted with the file key).
   * The uploader (possibly another album member) chooses its content, so only an
   * inline image is accepted: a URL such as "/logout" would otherwise make every
   * viewer's browser request it.
   */
  async decryptVideoPoster(mediaId, privateKey, encryptedPoster) {
    const { rawKeyB64 } = await this.getMediaContext(mediaId, privateKey);
    const poster = await this.decryptStringWithRawKey(encryptedPoster, rawKeyB64);
    if (!/^data:image\/[a-z0-9.+-]+[;,]/i.test(poster)) throw new Error('Video thumbnail is not an image');
    return poster;
  }

  // ─── Utilities ───────────────────────────────────────────────────────────────

  _buf2hex(buffer) {
    return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  _buf2b64(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  _b642buf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  _guessMime(filename) {
    if (!filename) return 'application/octet-stream';
    const ext = filename.split('.').pop().toLowerCase();
    const map = {
      jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
      gif: 'image/gif',  webp: 'image/webp', bmp: 'image/bmp',
      mp4: 'video/mp4',  webm: 'video/webm', mov: 'video/quicktime',
      avi: 'video/x-msvideo', mkv: 'video/x-matroska',
    };
    return map[ext] || 'application/octet-stream';
  }
}

// Singleton used by all templates
const e2e = new E2EEncryptionManager();

/**
 * Streaming decryption through the service worker (see sw.js): the page hands
 * the file key to the worker under a random token and uses /__stream/<token>/<name>
 * as a normal URL, e.g. as a <video> source (with seeking) or a download link.
 * Without a service worker (first visit before it activates, private windows in
 * some browsers) callers fall back to decrypting in memory.
 */
const e2eStream = (() => {
  const registered = new Map(); // token -> info (to re-send if the worker restarts)

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (event) => {
      const data = event.data || {};
      if (data.type === 'smg-need-stream' && event.ports[0]) {
        event.ports[0].postMessage(registered.get(data.token) || null);
      }
    });
  }

  async function controller(timeoutMs = 3000) {
    if (!('serviceWorker' in navigator) || !window.isSecureContext) return null;
    if (navigator.serviceWorker.controller) return navigator.serviceWorker.controller;
    // First visit: the worker claims the page once it has activated.
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(navigator.serviceWorker.controller), timeoutMs);
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        clearTimeout(timer);
        resolve(navigator.serviceWorker.controller);
      }, { once: true });
    });
  }

  /** Returns a same-origin URL serving the decrypted file, or null if streaming is unavailable. */
  async function url(info, { download = false } = {}) {
    const worker = await controller();
    if (!worker) return null;
    const token = crypto.randomUUID();
    const payload = {
      mediaId: info.mediaId, rawKeyB64: info.rawKeyB64, nonceB64: info.nonceB64,
      chunkSize: info.chunkSize, cipherSize: info.cipherSize, mime: info.mime, filename: info.filename,
    };
    registered.set(token, payload);
    const ok = await new Promise((resolve) => {
      const channel = new MessageChannel();
      const timer = setTimeout(() => resolve(false), 3000);
      channel.port1.onmessage = (event) => { clearTimeout(timer); resolve(event.data === 'ok'); };
      worker.postMessage({ type: 'smg-register-stream', token, info: payload }, [channel.port2]);
    });
    if (!ok) { registered.delete(token); return null; }
    return `/__stream/${token}/${encodeURIComponent(info.filename)}${download ? '?download=1' : ''}`;
  }

  function release(streamUrl) {
    const match = /^\/__stream\/([A-Za-z0-9-]+)\//.exec(streamUrl || '');
    if (!match) return;
    registered.delete(match[1]);
    navigator.serviceWorker?.controller?.postMessage({ type: 'smg-release-stream', token: match[1] });
  }

  return { url, release, isStreamUrl: (u) => /^\/__stream\//.test(u || '') };
})();

/** In-memory fallback limit when streaming is unavailable (protects the tab). */
const E2E_IN_MEMORY_LIMIT = 512 * 1024 * 1024;

/** Decrypt and save a media file under its original name. */
async function e2eDownloadMedia(mediaId, privateKey) {
  const info = await e2e.mediaFileInfo(mediaId, privateKey);
  let href = await e2eStream.url(info, { download: true });
  let objectUrl = null;
  if (!href) {
    if (info.plainSize > E2E_IN_MEMORY_LIMIT) {
      throw new Error('This file is too large to decrypt without the service worker. Reload the page and try again.');
    }
    const blob = await SMGChunked.decryptToBlob(await e2e._decryptInfo(info), info.mime);
    href = objectUrl = URL.createObjectURL(blob);
  }
  const link = document.createElement('a');
  link.href = href;
  link.download = info.filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Give the browser time to start the download before freeing anything.
  setTimeout(() => {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    else e2eStream.release(href);
  }, 60000);
}

/**
 * Resumable, chunked upload of one file (encrypt 4 MiB → PUT → next).
 * Memory use stays at a few chunks regardless of the file size.
 */
class E2EUploader {
  constructor(albumId, recipients) {
    this.albumId = albumId;
    this.recipients = recipients; // [{ id, publicKey: CryptoKey }]
    this.chunkSize = SMGChunked.DEFAULT_CHUNK_SIZE;
  }

  /** My unfinished uploads in this album, plus storage numbers. */
  async pending(privateKey) {
    const res = await fetch(`/api/album/${this.albumId}/uploads`);
    if (!res.ok) throw new Error(`Could not list unfinished uploads (${res.status})`);
    const data = await res.json();
    for (const upload of data.uploads) {
      try {
        upload.rawKeyB64 = await e2e.decryptKeyWithPrivateKey(upload.encrypted_key, privateKey);
        upload.filename = await e2e.decryptStringWithRawKey(upload.encrypted_filename, upload.rawKeyB64);
        upload.fingerprint = upload.encrypted_check
          ? await e2e.decryptStringWithRawKey(upload.encrypted_check, upload.rawKeyB64) : '';
      } catch {
        upload.filename = '(unreadable)';
      }
    }
    return data;
  }

  static async discard(token) {
    await fetch(`/api/uploads/${encodeURIComponent(token)}`, { method: 'DELETE' });
  }

  /** Identifies "the same file" when resuming: size, date and a hash of its start. */
  static async fingerprint(file) {
    const head = await file.slice(0, 1024 * 1024).arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', head);
    return `${file.size}:${file.lastModified}:${e2e._buf2hex(digest)}`;
  }

  /** The unfinished upload this file can continue, if any. */
  static async findResumable(file, pendingList) {
    const fp = await E2EUploader.fingerprint(file);
    return pendingList.find((p) => p.rawKeyB64 && p.filename === file.name && p.fingerprint === fp
      && p.total_size === SMGChunked.encryptedSize(file.size, p.chunk_size)) || null;
  }

  async _start(file, fileType, thumbnailDataUrl) {
    const fileKey = await e2e.generateFileKey();
    const rawKeyB64 = await e2e.exportRawKey(fileKey);
    const nonce = crypto.getRandomValues(new Uint8Array(SMGChunked.NONCE_BYTES));
    const keys = {};
    for (const recipient of this.recipients) {
      keys[recipient.id] = await e2e.encryptKeyForRecipient(rawKeyB64, recipient.publicKey);
    }
    const body = {
      file_type: fileType,
      encrypted_filename: await e2e.encryptStringWithRawKey(file.name, rawKeyB64),
      encrypted_check: await e2e.encryptStringWithRawKey(await E2EUploader.fingerprint(file), rawKeyB64),
      video_thumbnail: thumbnailDataUrl ? await e2e.encryptStringWithRawKey(thumbnailDataUrl, rawKeyB64) : null,
      nonce_b64: e2e._buf2b64(nonce),
      chunk_size: this.chunkSize,
      total_size: SMGChunked.encryptedSize(file.size, this.chunkSize),
      keys,
    };
    const { res, data } = await e2ePostJson(`/api/album/${this.albumId}/uploads`, body);
    if (res.status !== 201) throw new Error(data.error || `Could not start the upload (${res.status})`);
    return { ...data, rawKeyB64 };
  }

  async _putChunk(token, offset, bytes, signal) {
    // Sent as a Blob: Chromium keeps fetch() ArrayBuffer bodies in memory long after
    // the request (measured: a 1.5 GB upload grew the tab by 1.5 GB); Blob bodies are freed.
    const body = new Blob([bytes], { type: 'application/octet-stream' });
    let delay = 1000;
    for (let attempt = 1; ; attempt++) {
      let res;
      try {
        res = await fetch(`/api/uploads/${encodeURIComponent(token)}?offset=${offset}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body, signal,
        });
      } catch (err) {
        if (signal?.aborted) throw err;
        res = null; // network error: retry
      }
      if (res?.ok) return (await res.json()).received;
      if (res?.status === 409) return (await res.json()).received; // server already has more/less
      if (res && res.status < 500 && res.status !== 408 && res.status !== 429) {
        let message = `Upload failed (${res.status})`;
        try { message = (await res.json()).error || message; } catch { /* not JSON */ }
        throw new Error(message);
      }
      if (attempt >= 8) throw new Error('Upload failed after several retries; select the file again later to resume.');
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, 15000);
    }
  }

  /**
   * Upload (or continue uploading) one file.
   * options: { fileType, thumbnailDataUrl, resume (entry from pending()), signal, onProgress(sent, total) }
   */
  async upload(file, { fileType, thumbnailDataUrl = '', resume = null, signal = null, onProgress = () => {} }) {
    const upload = resume || await this._start(file, fileType, thumbnailDataUrl);
    const chunkSize = upload.chunk_size;
    const { stride, count } = SMGChunked.layout(upload.total_size, chunkSize);
    const key = await crypto.subtle.importKey('raw', e2e._b642buf(upload.rawKeyB64), e2e.aesAlgo, false, ['encrypt']);
    const nonce = new Uint8Array(e2e._b642buf(upload.nonce_b64));

    const encrypt = async (index) => {
      const plain = await file.slice(index * chunkSize, Math.min(file.size, (index + 1) * chunkSize)).arrayBuffer();
      return SMGChunked.encryptChunk(key, nonce, index, index === count - 1, plain);
    };

    let received = upload.received || 0;
    onProgress(received, upload.total_size);
    let encrypting = received < upload.total_size ? encrypt(received / stride) : null;
    while (received < upload.total_size) {
      if (signal?.aborted) throw new DOMException('Upload cancelled', 'AbortError');
      const index = received / stride;
      const cipher = await encrypting;
      // Encrypt the next chunk while this one is being sent.
      encrypting = index + 1 < count ? encrypt(index + 1) : null;
      const after = await this._putChunk(upload.token, received, cipher, signal);
      if (after === received) throw new Error('The server did not accept the chunk.');
      if (after !== received + cipher.byteLength) {
        // The server had a different position (e.g. an earlier attempt got through): follow it.
        encrypting = after < upload.total_size ? encrypt(after / stride) : null;
      }
      received = after;
      onProgress(received, upload.total_size);
    }

    const { res, data } = await e2ePostJson(`/api/uploads/${encodeURIComponent(upload.token)}/complete`, {});
    if (!res.ok) throw new Error(data.error || `Could not finish the upload (${res.status})`);
    return data;
  }
}

/**
 * Browsers expose crypto.subtle only in secure contexts: HTTPS, or plain HTTP on
 * localhost / 127.0.0.1. Returns an error message, or null if encryption works.
 */
function e2eSecureContextError() {
  if (window.isSecureContext && window.crypto && crypto.subtle) return null;
  return 'Encryption is unavailable: this page must be opened via HTTPS ' +
         '(or http://localhost / http://127.0.0.1 for local testing).';
}

/** Small helper for JSON POSTs that return JSON (used by login/register). */
async function e2ePostJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  return { res, data };
}

/**
 * Fingerprint / face unlock ("device unlock") using a passkey with the PRF extension.
 *
 * Enrolling creates a passkey on this device's built-in authenticator. Each
 * successful fingerprint/face check (or device PIN) makes the authenticator
 * return the same secret (PRF output) for our salt. We derive an AES key from
 * it and encrypt { auth_key, wrap_key } with it. The ciphertext stays in this
 * browser's localStorage; the server is not involved and learns nothing new.
 *
 *   fingerprint → PRF secret → AES key → { auth_key (sign in), wrap_key (unlock) }
 *
 * Anyone who can pass the device's user verification can therefore sign in on
 * this device, just like a saved password. Remove it from the Keys page.
 */
const DEVICE_UNLOCK_STORAGE = 'e2e_device_unlock_v1';
const DEVICE_UNLOCK_HKDF_INFO = 'secure-media-gallery|device-unlock|v1';

class DeviceUnlock {
  _load() {
    try {
      const data = JSON.parse(localStorage.getItem(DEVICE_UNLOCK_STORAGE) || '{}');
      return data && typeof data === 'object' ? data : {};
    } catch {
      return {};
    }
  }

  _save(entries) {
    localStorage.setItem(DEVICE_UNLOCK_STORAGE, JSON.stringify(entries));
  }

  /** Usernames with fingerprint unlock set up on this device. */
  enrolledUsernames() {
    return Object.keys(this._load()).sort();
  }

  isEnrolled(username) {
    return Object.hasOwn(this._load(), e2e.normalizeUsername(username));
  }

  remove(username) {
    const entries = this._load();
    const entry = entries[e2e.normalizeUsername(username)];
    delete entries[e2e.normalizeUsername(username)];
    this._save(entries);
    // Ask the device to drop the now unused passkey from its list (newer browsers only).
    if (entry && typeof PublicKeyCredential?.signalUnknownCredential === 'function') {
      const credentialId = entry.credential_id.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId }).catch(() => {});
    }
  }

  /**
   * Returns null if this browser/device can be used, otherwise a reason to show.
   * (Whether the authenticator really supports PRF is only certain after enrolling.)
   */
  async unsupportedReason() {
    if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
      return 'This browser does not support passkeys here (HTTPS is required).';
    }
    let platform = false;
    try {
      platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch { /* treated as unavailable */ }
    if (!platform) return 'This device has no built-in fingerprint/face/PIN authenticator available to the browser.';
    if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
      try {
        const caps = await PublicKeyCredential.getClientCapabilities();
        if (caps['extension:prf'] === false) return 'This browser does not support the passkey PRF extension.';
      } catch { /* unknown: try anyway */ }
    }
    return null;
  }

  async _aesKey(prfOutput, salt) {
    const base = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(DEVICE_UNLOCK_HKDF_INFO) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
  }

  async _prf(credentialId, salt) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        // No server round trip: the assertion is not used for authentication,
        // only the PRF output is, so a random challenge is fine.
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: credentialId }],
        userVerification: 'required',
        timeout: 60000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    const first = assertion?.getClientExtensionResults()?.prf?.results?.first;
    if (!first) throw new Error('The authenticator did not return a PRF result.');
    return first;
  }

  /**
   * Set up fingerprint unlock for `username` on this device. The caller must
   * have verified that authKeyHex/wrapKeyB64 belong to the account.
   */
  async enroll(username, authKeyHex, wrapKeyB64) {
    const name = e2e.normalizeUsername(username);
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'Secure Media Gallery' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name, displayName: name },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'discouraged',
          userVerification: 'required',
        },
        timeout: 60000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    const prf = credential.getClientExtensionResults()?.prf;
    if (!prf || prf.enabled === false) {
      throw new Error('This authenticator does not support the PRF extension needed for unlocking.');
    }
    const credentialId = new Uint8Array(credential.rawId);
    // Some authenticators only return PRF results on use, not on creation: ask once more.
    const prfOutput = prf.results?.first || await this._prf(credentialId, salt);

    const key = await this._aesKey(prfOutput, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = new TextEncoder().encode(JSON.stringify({ auth_key: authKeyHex, wrap_key: wrapKeyB64 }));
    const data = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(name) }, key, payload,
    );
    const entries = this._load();
    entries[name] = {
      credential_id: e2e._buf2b64(credentialId),
      salt: e2e._buf2b64(salt),
      iv: e2e._buf2b64(iv),
      data: e2e._buf2b64(data),
      created: new Date().toISOString(),
    };
    this._save(entries);
  }

  /** Fingerprint check → { authKeyHex, wrapKeyB64 }. Throws if cancelled or failed. */
  async unlock(username) {
    const name = e2e.normalizeUsername(username);
    const entry = this._load()[name];
    if (!entry) throw new Error('Fingerprint unlock is not set up for this account on this device.');
    const salt = new Uint8Array(e2e._b642buf(entry.salt));
    const prfOutput = await this._prf(new Uint8Array(e2e._b642buf(entry.credential_id)), salt);
    const key = await this._aesKey(prfOutput, salt);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: e2e._b642buf(entry.iv), additionalData: new TextEncoder().encode(name) },
      key, e2e._b642buf(entry.data),
    );
    const { auth_key: authKeyHex, wrap_key: wrapKeyB64 } = JSON.parse(new TextDecoder().decode(plain));
    return { authKeyHex, wrapKeyB64 };
  }
}

const deviceUnlock = new DeviceUnlock();
