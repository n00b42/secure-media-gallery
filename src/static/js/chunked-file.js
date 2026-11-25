/**
 * Chunked file encryption, shared by the pages and the service worker.
 *
 * Format (per file, with its own random AES-256-GCM key):
 *   - the plaintext is split into chunkSize pieces (4 MiB); an empty file is one empty chunk
 *   - chunk i is encrypted with IV = nonce (8 random bytes) || i (uint32, big endian)
 *     and additional data = i (uint32) || final flag (1 byte, 1 for the last chunk)
 *   - the encrypted chunks are concatenated; each is chunkSize + 16 bytes (GCM tag),
 *     except the last one
 *
 * Binding the index and the final flag into every chunk means chunks can't be
 * reordered, swapped between files (different key) or cut off without
 * decryption failing. Because chunks are independent, any byte range can be
 * decrypted on its own: this is what makes streaming and seeking possible.
 */
const SMGChunked = (() => {
  const TAG = 16;
  const NONCE_BYTES = 8;
  const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

  function chunkIv(nonce, index) {
    const iv = new Uint8Array(12);
    iv.set(nonce, 0);
    new DataView(iv.buffer).setUint32(8, index);
    return iv;
  }

  function chunkAad(index, final) {
    const aad = new Uint8Array(5);
    new DataView(aad.buffer).setUint32(0, index);
    aad[4] = final ? 1 : 0;
    return aad;
  }

  function chunkCount(plainSize, chunkSize) {
    return Math.max(1, Math.ceil(plainSize / chunkSize));
  }

  /** Ciphertext size for a plaintext size. */
  function encryptedSize(plainSize, chunkSize) {
    return plainSize + chunkCount(plainSize, chunkSize) * TAG;
  }

  /** { stride, count, plainSize } for a ciphertext size. */
  function layout(cipherSize, chunkSize) {
    const stride = chunkSize + TAG;
    const count = Math.max(1, Math.ceil(cipherSize / stride));
    return { stride, count, plainSize: cipherSize - count * TAG };
  }

  function encryptChunk(key, nonce, index, final, plain) {
    return crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv(nonce, index), additionalData: chunkAad(index, final) }, key, plain,
    );
  }

  function decryptChunk(key, nonce, index, final, cipher) {
    return crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: chunkIv(nonce, index), additionalData: chunkAad(index, final) }, key, cipher,
    );
  }

  function _concat(pieces, total) {
    const out = new Uint8Array(total);
    let pos = 0;
    for (const piece of pieces) { out.set(piece, pos); pos += piece.length; }
    return out;
  }

  /** Small LRU of decrypted chunks: media players re-request the same region a lot. */
  class ChunkCache {
    constructor(limit = 8) { this.limit = limit; this.map = new Map(); }
    get(index) {
      const value = this.map.get(index);
      if (value) { this.map.delete(index); this.map.set(index, value); }
      return value;
    }
    set(index, value) {
      this.map.set(index, value);
      while (this.map.size > this.limit) this.map.delete(this.map.keys().next().value);
    }
  }

  /**
   * ReadableStream of plaintext bytes start..end (inclusive).
   * info: { key: CryptoKey, nonce: Uint8Array, chunkSize, cipherSize,
   *         fetchCipher(from, to, signal) -> Promise<Response> (byte range of the ciphertext),
   *         cache?: ChunkCache }
   * Only the chunks covering the range are fetched and decrypted, one at a time;
   * chunks already in info.cache are served without any network request.
   */
  function decryptRange(info, start, end) {
    const { stride, count } = layout(info.cipherSize, info.chunkSize);
    const first = Math.floor(start / info.chunkSize);
    const last = Math.min(count - 1, Math.floor(end / info.chunkSize));
    const cipherTo = Math.min(info.cipherSize, (last + 1) * stride) - 1;
    const abort = new AbortController();
    let reader = null;
    let pieces = [];
    let buffered = 0;
    let skip = 0; // bytes to drop if the server ignored the Range header
    let index = first;

    async function openAt(chunkIndex) {
      const from = chunkIndex * stride;
      const response = await info.fetchCipher(from, cipherTo, abort.signal);
      if (response.status === 200) skip = from;
      else if (response.status !== 206) throw new Error(`File fetch failed: ${response.status}`);
      reader = response.body.getReader();
    }

    async function readExactly(n) {
      while (buffered < n + skip) {
        const { done, value } = await reader.read();
        if (done) throw new Error('Encrypted file is truncated');
        pieces.push(value);
        buffered += value.length;
      }
      const all = _concat(pieces, buffered);
      const bytes = all.subarray(skip, skip + n);
      const rest = all.subarray(skip + n);
      pieces = rest.length ? [rest] : [];
      buffered = rest.length;
      skip = 0;
      return bytes;
    }

    async function chunkPlaintext(chunkIndex) {
      if (!reader) {
        // Serve leading chunks from the cache; at the first miss, start downloading
        // from that chunk. After that, the network stream is read strictly in order.
        const cached = info.cache?.get(chunkIndex);
        if (cached) return cached;
        await openAt(chunkIndex);
      }
      const final = chunkIndex === count - 1;
      const need = final ? info.cipherSize - chunkIndex * stride : stride;
      const cipher = await readExactly(need);
      const plain = new Uint8Array(await decryptChunk(info.key, info.nonce, chunkIndex, final, cipher));
      info.cache?.set(chunkIndex, plain);
      return plain;
    }

    return new ReadableStream({
      async pull(controller) {
        const plain = await chunkPlaintext(index);
        const chunkStart = index * info.chunkSize;
        const from = Math.max(0, start - chunkStart);
        const to = Math.min(plain.length, end - chunkStart + 1);
        if (to > from) controller.enqueue(plain.subarray(from, to));
        index += 1;
        if (index > last) {
          controller.close();
          abort.abort(); // stop downloading anything past the requested range
        }
      },
      cancel() {
        abort.abort();
        if (reader) reader.cancel().catch(() => {});
      },
    }, { highWaterMark: 1 });
  }

  /** Decrypt a whole file into a Blob (images and small files). */
  async function decryptToBlob(info, type) {
    const { plainSize } = layout(info.cipherSize, info.chunkSize);
    if (plainSize === 0) return new Blob([], { type });
    const parts = [];
    const reader = decryptRange(info, 0, plainSize - 1).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    return new Blob(parts, { type });
  }

  /** fetchCipher implementation for a media item (page or service worker). */
  function mediaFetcher(mediaId) {
    return (from, to, signal) => fetch(`/media/${mediaId}/raw`, {
      headers: { Range: `bytes=${from}-${to}` },
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
    });
  }

  return {
    TAG, NONCE_BYTES, DEFAULT_CHUNK_SIZE,
    chunkCount, encryptedSize, layout, encryptChunk, decryptChunk, decryptRange, decryptToBlob, mediaFetcher, ChunkCache,
  };
})();
