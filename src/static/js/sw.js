/*
 * Service worker for the installable app (PWA). Served at /sw.js so that it
 * controls the whole site.
 *
 * Deliberately minimal:
 *   - Static files whose URL carries a content hash (?v=…) are cached and
 *     served from the cache: they never change under the same URL.
 *   - Page loads go to the network; when offline, a short notice is shown.
 *   - /__stream/<token>/<name> URLs are answered by decrypting the encrypted
 *     file chunk by chunk (videos with seeking, and downloads straight to
 *     disk). The page registers the file key for a token; keys live only in
 *     this worker's memory and are re-requested from the page when needed.
 *   - Nothing else is intercepted. Album pages, API responses and encrypted
 *     media are never stored on the device.
 */

// Replaced by the /sw.js route with the content-hashed URL of chunked-file.js.
importScripts('__CHUNKED_FILE_URL__');

const STATIC_CACHE = 'smg-static-v1';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const name of await caches.keys()) {
      if (name !== STATIC_CACHE) await caches.delete(name);
    }
    await self.clients.claim();
  })());
});

async function cachedStatic(request) {
  const cache = await caches.open(STATIC_CACHE);
  const hit = await cache.match(request);
  if (hit) return hit;

  const response = await fetch(request);
  if (response.ok) {
    // Drop older versions of the same file so the cache doesn't grow forever.
    const path = new URL(request.url).pathname;
    for (const old of await cache.keys()) {
      if (new URL(old.url).pathname === path) await cache.delete(old);
    }
    await cache.put(request, response.clone());
  }
  return response;
}

const OFFLINE_PAGE = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Offline - Secure Media Gallery</title>
<style>
  body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh;
         margin: 0; background: #121316; color: #e4e5e8; text-align: center; padding: 24px; }
  p { color: #9a9ea7; }
</style></head>
<body><div><h1>🔒 You're offline</h1>
<p>The gallery needs a connection to load your encrypted files.<br>Reconnect and reload the page.</p>
</div></body></html>`;

// ── Decrypting stream endpoint ─────────────────────────────────────────────

const streams = new Map(); // token -> Promise<info>

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function prepare(info) {
  const key = await crypto.subtle.importKey(
    'raw', b64ToBytes(info.rawKeyB64), { name: 'AES-GCM' }, false, ['decrypt'],
  );
  return {
    key,
    nonce: b64ToBytes(info.nonceB64),
    chunkSize: info.chunkSize,
    cipherSize: info.cipherSize,
    mime: info.mime || 'application/octet-stream',
    filename: info.filename || 'download',
    fetchCipher: SMGChunked.mediaFetcher(info.mediaId),
    cache: new SMGChunked.ChunkCache(8), // last 8 decrypted chunks (32 MiB) of this file
  };
}

function askClient(client, token) {
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => resolve(null), 2000);
    channel.port1.onmessage = (event) => { clearTimeout(timer); resolve(event.data); };
    client.postMessage({ type: 'smg-need-stream', token }, [channel.port2]);
  });
}

async function lookupStream(token) {
  if (!streams.has(token)) {
    // The worker may have been restarted and lost its memory: ask the open pages.
    for (const client of await self.clients.matchAll({ type: 'window' })) {
      const info = await askClient(client, token);
      if (info) {
        streams.set(token, prepare(info));
        break;
      }
    }
  }
  return streams.get(token) || null;
}

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'smg-register-stream') {
    streams.set(data.token, prepare(data.info));
    streams.get(data.token).then(
      () => event.ports[0]?.postMessage('ok'),
      () => event.ports[0]?.postMessage('error'),
    );
  } else if (data.type === 'smg-release-stream') {
    streams.delete(data.token);
  }
});

function contentDisposition(filename) {
  const ascii = filename.replace(/[^\x20-\x7e]|["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename)}`;
}

async function streamResponse(request, token, download) {
  const info = await lookupStream(token);
  if (!info) return new Response('Unknown or expired stream', { status: 404 });
  const { plainSize } = SMGChunked.layout(info.cipherSize, info.chunkSize);
  const headers = {
    'Content-Type': info.mime,
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'no-store',
  };
  if (download) headers['Content-Disposition'] = contentDisposition(info.filename);

  let start = 0;
  let end = plainSize - 1;
  let status = 200;
  const range = /^bytes=(\d*)-(\d*)$/.exec(request.headers.get('Range') || '');
  if (range && plainSize > 0) {
    if (range[1] === '') { // suffix range: last N bytes
      start = Math.max(0, plainSize - Number(range[2]));
    } else {
      start = Number(range[1]);
      // Open-ended requests ("bytes=N-") get the rest of the file: the stream is
      // pulled as the player consumes it and cancelled when it seeks elsewhere.
      // (Capping the answer made Chromium re-request the same range many times.)
      if (range[2] !== '') end = Math.min(end, Number(range[2]));
    }
    if (start > end || start >= plainSize) {
      return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${plainSize}` } });
    }
    status = 206;
    headers['Content-Range'] = `bytes ${start}-${end}/${plainSize}`;
  }
  headers['Content-Length'] = String(plainSize === 0 ? 0 : end - start + 1);
  const body = plainSize === 0 ? null : SMGChunked.decryptRange(info, start, end);
  return new Response(body, { status, headers });
}

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  const stream = /^\/__stream\/([A-Za-z0-9-]+)\//.exec(url.pathname);
  if (stream) {
    event.respondWith(streamResponse(request, stream[1], url.searchParams.has('download')));
    return;
  }

  if (url.pathname.startsWith('/static/') && url.searchParams.has('v')) {
    event.respondWith(cachedStatic(request));
    return;
  }

  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).catch(() => new Response(OFFLINE_PAGE, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    })));
  }
});
