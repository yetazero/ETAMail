import { secp256k1 }  from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export default {

  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return corsPreflightResponse(request, env);
    const url = new URL(request.url);
    const p   = url.pathname;
    try {
      if (p === '/auth/challenge'  && request.method === 'POST')   return await handleChallenge(request, env);
      if (p === '/auth/verify'     && request.method === 'POST')   return await handleVerify(request, env);
      if (p === '/auth/logout'     && request.method === 'DELETE') return await handleLogout(request, env);
      if (p === '/auth/me'         && request.method === 'GET')    return await handleMe(request, env);
      if (p === '/auth/qr-init'    && request.method === 'POST')   return await handleQrInit(request, env);
      if (p === '/auth/qr-poll'    && request.method === 'GET')    return await handleQrPoll(request, env);
      if (p === '/auth/qr-confirm' && request.method === 'POST')   return await handleQrConfirm(request, env);
      if (p === '/list'   && request.method === 'GET')    return await withAuth(request, env, handleList);
      if (p === '/get'    && request.method === 'GET')    return await withAuth(request, env, handleGet);
      if (p === '/put'    && request.method === 'POST')   return await withAuth(request, env, handlePut);
      if (p === '/delete' && request.method === 'DELETE') return await withAuth(request, env, handleDelete);
      return jsonResponse({ error: 'Not found' }, 404, request, env);
    } catch (err) {
      console.error('[Worker Error]', err);
      return jsonResponse({ error: 'Internal server error' }, 500, request, env);
    }
  },

  async email(message, env, ctx) {
    try {
      const rawBytes = await new Response(message.raw).arrayBuffer();
      const rawText  = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
      const parsed   = parseMime(rawText);

      const sender  = message.from              || parsed.headers['from']  || 'unknown@sender';
      const subject = parsed.headers['subject'] || '(no subject)';
      const date    = parsed.headers['date']    || new Date().toISOString();
      const to      = message.to                || parsed.headers['to']    || '';

      const body   = parsed.html
        ? inlineCidImages(parsed.html, parsed.attachments)
        : (parsed.text || '(empty)');
      const isHtml = !!parsed.html;

      const payload = JSON.stringify({
        subject, from: sender, to, date, body, isHtml,
        attachments: parsed.attachments
          .filter(a => !a.contentId)
          .map(a => ({ name: a.name, type: a.type, data: a.data, size: a.size })),
      });

      const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const iv     = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload));
      const rawKey = await crypto.subtle.exportKey('raw', aesKey);

      const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
      const blob  = { iv: toB64(iv.buffer), key: toB64(rawKey), payload: toB64(cipher) };

      const owner = (env.ALLOWED_ADDRESS || 'unknown').toLowerCase();
      const msgId = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`;
      const kvKey = `email:${owner}:${msgId}`;

      await env.EMAILS_KV.put(kvKey, JSON.stringify(blob), {
        metadata: {
          sender:  sender.slice(0, 200),
          subject: subject.slice(0, 300),
          date,
          folder:  'inbox',
          unread:  true,
        },
      });

      console.log(`[email] saved ${kvKey} | from: ${sender} | subject: ${subject}`);
    } catch (err) {
      console.error('[email] error:', err?.message || err);
    }
  },
};

async function handleChallenge(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }

  const address = (body.address || '').toLowerCase().trim();
  if (!isValidEthAddress(address)) {
    return jsonResponse({ error: 'Invalid wallet address' }, 400, request, env);
  }

  const allowed = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowed && address !== allowed) {
    return jsonResponse({ error: 'This wallet address is not allowed' }, 403, request, env);
  }

  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce      = bytesToHex(nonceBytes);
  const issuedAt   = new Date().toISOString();
  const ttl        = parseInt(env.NONCE_TTL || '300');

  const reqUrl  = new URL(request.url);
  const domain  = reqUrl.hostname;
  const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');

  const message = buildSiweMessage({
    domain,
    address,
    statement: 'Sign in to ETAMail. This request will not trigger a blockchain transaction or cost any fees.',
    uri:       `https://${domain}`,
    version:   '1',
    chainId,
    nonce,
    issuedAt,
  });

  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({
    address,
    nonce,
    issuedAt,
    used: false,
  }), { expirationTtl: ttl });

  return jsonResponse({ message, nonce, address, issuedAt, expiresIn: ttl }, 200, request, env);
}

async function handleVerify(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }

  const { address, signature, nonce } = body;
  if (!address || !signature || !nonce) {
    return jsonResponse({ error: 'Required: address, signature, nonce' }, 400, request, env);
  }

  const addrLower = address.toLowerCase().trim();
  const nonceData = await env.AUTH_KV.get(`nonce:${nonce}`, 'json');

  if (!nonceData)              return jsonResponse({ error: 'Nonce not found or expired' }, 401, request, env);
  if (nonceData.used)          return jsonResponse({ error: 'Nonce already used' }, 401, request, env);
  if (nonceData.address !== addrLower) return jsonResponse({ error: 'Address mismatch' }, 401, request, env);

  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env);
  if (recovered !== addrLower) {
    return jsonResponse({ error: `Invalid signature. Recovered: ${recovered}` }, 401, request, env);
  }

  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({ ...nonceData, used: true }), { expirationTtl: 60 });

  const sessionTtl = parseInt(env.SESSION_TTL || '86400');
  const token      = await generateSessionToken(addrLower, env.JWT_SECRET || 'change-me', sessionTtl);

  await env.AUTH_KV.put(`session:${token}`, JSON.stringify({
    address:   addrLower,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
  }), { expirationTtl: sessionTtl });

  return jsonResponse({
    token,
    address:   addrLower,
    expiresIn: sessionTtl,
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
    message:   '✓ Authorized',
  }, 200, request, env);
}

async function handleLogout(request, env) {
  const token = extractToken(request);
  if (token) await env.AUTH_KV.delete(`session:${token}`);
  return jsonResponse({ message: 'Logged out' }, 200, request, env);
}

async function handleMe(request, env) {
  const token = extractToken(request);
  if (!token) return jsonResponse({ authenticated: false }, 200, request, env);
  const session = await env.AUTH_KV.get(`session:${token}`, 'json');
  if (!session)  return jsonResponse({ authenticated: false }, 200, request, env);
  return jsonResponse({ authenticated: true, address: session.address, createdAt: session.createdAt, expiresAt: session.expiresAt }, 200, request, env);
}

async function handleQrInit(request, env) {
  const sessionId = crypto.randomUUID();
  const ttl       = 300;

  await env.AUTH_KV.put(`qr:${sessionId}`, JSON.stringify({
    status:    'pending',
    createdAt: new Date().toISOString(),
    address:   null,
    token:     null,
  }), { expirationTtl: ttl });

  const origin = request.headers.get('Origin') || `https://${new URL(request.url).hostname}`;
  const url    = `${origin}?qr=${sessionId}`;

  return jsonResponse({ sessionId, url, expiresIn: ttl }, 200, request, env);
}

async function handleQrPoll(request, env) {
  const sessionId = new URL(request.url).searchParams.get('session');
  if (!sessionId) return jsonResponse({ error: 'session param required' }, 400, request, env);

  const qrData = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!qrData)  return jsonResponse({ status: 'expired' }, 200, request, env);

  if (qrData.status === 'verified') {
    return jsonResponse({ status: 'verified', token: qrData.token, address: qrData.address }, 200, request, env);
  }

  return jsonResponse({ status: 'pending' }, 200, request, env);
}

async function handleQrConfirm(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }

  const { sessionId, address, signature, nonce } = body;
  if (!sessionId || !address || !signature || !nonce) {
    return jsonResponse({ error: 'Required: sessionId, address, signature, nonce' }, 400, request, env);
  }

  const qrData = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!qrData)                     return jsonResponse({ error: 'QR session not found or expired' }, 404, request, env);
  if (qrData.status !== 'pending') return jsonResponse({ error: 'QR session already used' }, 409, request, env);

  const addrLower = address.toLowerCase().trim();
  const allowed   = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowed && addrLower !== allowed) {
    return jsonResponse({ error: 'This wallet address is not allowed' }, 403, request, env);
  }

  const nonceData = await env.AUTH_KV.get(`nonce:${nonce}`, 'json');
  if (!nonceData)              return jsonResponse({ error: 'Nonce not found or expired' }, 401, request, env);
  if (nonceData.used)          return jsonResponse({ error: 'Nonce already used' }, 401, request, env);
  if (nonceData.address !== addrLower) return jsonResponse({ error: 'Address mismatch' }, 401, request, env);

  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env);
  if (recovered !== addrLower) {
    return jsonResponse({ error: `Invalid signature. Recovered: ${recovered}` }, 401, request, env);
  }

  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({ ...nonceData, used: true }), { expirationTtl: 60 });

  const sessionTtl = parseInt(env.SESSION_TTL || '86400');
  const token      = await generateSessionToken(addrLower, env.JWT_SECRET || 'change-me', sessionTtl);

  await env.AUTH_KV.put(`session:${token}`, JSON.stringify({
    address:   addrLower,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
  }), { expirationTtl: sessionTtl });

  await env.AUTH_KV.put(`qr:${sessionId}`, JSON.stringify({
    status:  'verified',
    address: addrLower,
    token,
  }), { expirationTtl: 120 });

  return jsonResponse({ token, address: addrLower, message: '✓ QR login successful' }, 200, request, env);
}

async function withAuth(request, env, handler) {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: 'Authorization required' }, 401, request, env);

  const session = await env.AUTH_KV.get(`session:${token}`, 'json');
  if (!session)  return jsonResponse({ error: 'Session invalid or expired' }, 401, request, env);

  if (new Date(session.expiresAt) < new Date()) {
    await env.AUTH_KV.delete(`session:${token}`);
    return jsonResponse({ error: 'Session expired' }, 401, request, env);
  }

  return handler(request, env, session);
}

async function handleList(request, env, session) {
  const prefix = `email:${session.address}:`;
  const listed = await env.EMAILS_KV.list({ prefix });

  const headers = listed.keys.map(k => {
    const meta = k.metadata || {};
    return {
      key:     k.name,
      sender:  meta.sender  || 'Encrypted',
      subject: meta.subject || 'Encrypted',
      date:    meta.date    || null,
      folder:  meta.folder  || 'inbox',
      unread:  meta.unread  !== undefined ? meta.unread : true,
    };
  });

  headers.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  return jsonResponse({ messages: headers, total: headers.length }, 200, request, env);
}

async function handleGet(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');
  if (!key) return jsonResponse({ error: 'key param required' }, 400, request, env);
  if (!key.startsWith(`email:${session.address}:`)) return jsonResponse({ error: 'Forbidden' }, 403, request, env);

  const blob = await env.EMAILS_KV.get(key, 'json');
  if (!blob)  return jsonResponse({ error: 'Not found' }, 404, request, env);

  return jsonResponse(blob, 200, request, env);
}

async function handlePut(request, env, session) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }

  if (!body.iv || !body.payload) {
    return jsonResponse({ error: 'iv and payload required' }, 400, request, env);
  }

  const msgId = generateMsgId();
  const kvKey = `email:${session.address}:${msgId}`;
  const meta  = body.meta || {};
  const now   = new Date().toISOString();

  await env.EMAILS_KV.put(kvKey, JSON.stringify({
    iv:      body.iv,
    key:     body.key || null,
    payload: body.payload,
  }), {
    metadata: {
      sender:  meta.sender  || 'Unknown sender',
      subject: meta.subject || '(encrypted)',
      date:    meta.date    || now,
      folder:  meta.folder  || 'inbox',
      unread:  true,
    },
  });

  return jsonResponse({ key: kvKey, message: 'Saved', date: now }, 201, request, env);
}

async function handleDelete(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');
  if (!key) return jsonResponse({ error: 'key param required' }, 400, request, env);
  if (!key.startsWith(`email:${session.address}:`)) return jsonResponse({ error: 'Forbidden' }, 403, request, env);

  const blob = await env.EMAILS_KV.get(key);
  if (!blob)  return jsonResponse({ error: 'Not found' }, 404, request, env);

  await env.EMAILS_KV.delete(key);
  return jsonResponse({ key, message: '✓ Deleted', deletedAt: new Date().toISOString() }, 200, request, env);
}

function recoverEthAddress(address, nonce, issuedAt, signature, env) {
  try {
    const reqUrl  = new URL('https://placeholder');
    const domain  = 'worker.yetazero.xyz';
    const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');

    const message = buildSiweMessage({
      domain,
      address,
      statement: 'Sign in to ETAMail. This request will not trigger a blockchain transaction or cost any fees.',
      uri:       `https://${domain}`,
      version:   '1',
      chainId,
      nonce,
      issuedAt,
    });

    const msgBytes = new TextEncoder().encode(message);
    const prefix   = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
    const prefixed = concatBytes(prefix, msgBytes);
    const msgHash  = keccak_256(prefixed);

    const sigHex   = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBytes = hexToBytes(sigHex);
    if (sigBytes.length !== 65) throw new Error(`Bad signature length: ${sigBytes.length}`);

    const r  = bytesToHex(sigBytes.slice(0, 32));
    const s  = bytesToHex(sigBytes.slice(32, 64));
    let   v  = sigBytes[64];
    if (v >= 27) v -= 27;

    const sig        = secp256k1.Signature.fromCompact(`${r}${s}`).addRecoveryBit(v);
    const pubKeyObj  = sig.recoverPublicKey(msgHash);
    const pubKeyData = pubKeyObj.toRawBytes(false).slice(1);
    const addrHash   = keccak_256(pubKeyData);

    return ('0x' + bytesToHex(addrHash.slice(-20))).toLowerCase();
  } catch (err) {
    console.error('[recoverEthAddress]', err);
    return '0x_recovery_failed';
  }
}

function buildSiweMessage({ domain, address, statement, uri, version, chainId, nonce, issuedAt }) {
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    '',
    statement,
    '',
    `URI: ${uri}`,
    `Version: ${version}`,
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${issuedAt}`,
  ].join('\n');
}

function getChainId(chainName) {
  const chains = {
    'Ethereum':        1,
    'BNB Smart Chain': 56,
    'Polygon':         137,
    'Avalanche':       43114,
    'Arbitrum':        42161,
    'Optimism':        10,
  };
  return chains[chainName] || 1;
}

async function generateSessionToken(address, secret, ttl) {
  const payload   = {
    sub: address,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttl,
    jti: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
  };
  const payloadB64 = btoa(JSON.stringify(payload));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', keyMaterial, new TextEncoder().encode(payloadB64));
  const sigB64 = arrayBufferToBase64url(sigBuf);
  return `${payloadB64}.${sigB64}`;
}

function parseMime(raw) {
  const result = { headers: {}, text: '', html: '', attachments: [], _root: true };
  parsePart(raw, result);
  return result;
}

function parsePart(raw, result) {
  const split    = raw.indexOf('\r\n\r\n');
  const hdrBlock = split !== -1 ? raw.slice(0, split) : raw;
  const body     = split !== -1 ? raw.slice(split + 4) : '';
  const headers  = parseHeaders(hdrBlock);

  if (result._root) { result.headers = { ...result.headers, ...headers }; delete result._root; }

  const ct       = headers['content-type'] || 'text/plain';
  const ctLower  = ct.toLowerCase();
  const enc      = (headers['content-transfer-encoding'] || '').toLowerCase().trim();
  const cid      = (headers['content-id'] || '').replace(/[<>]/g, '').trim();
  const disp     = (headers['content-disposition'] || '').toLowerCase();
  const isAttach = disp.startsWith('attachment');

  if (ctLower.startsWith('multipart/')) {
    const bm = ct.match(/boundary\s*=\s*"?([^";]+)"?/i);
    if (!bm) return;
    for (const part of splitMultipart(body, bm[1].trim())) parsePart(part, result);
    return;
  }

  let decoded = enc === 'base64'           ? body.replace(/\s/g, '')
              : enc === 'quoted-printable' ? decodeQP(body)
              : body;

  const csm     = ct.match(/charset\s*=\s*"?([^";]+)"?/i);
  const charset = csm ? csm[1].trim() : 'utf-8';

  if (ctLower.startsWith('text/html') && !isAttach) {
    result.html += enc === 'base64' ? b64Decode(decoded, charset) : decoded;
    return;
  }
  if (ctLower.startsWith('text/plain') && !isAttach) {
    result.text += enc === 'base64' ? b64Decode(decoded, charset) : decoded;
    return;
  }

  const namem = ct.match(/name\s*=\s*"?([^";]+)"?/i) || disp.match(/filename\s*=\s*"?([^";]+)"?/i);
  const name  = namem ? namem[1].trim() : (cid || 'attachment');
  const b64   = enc === 'base64' ? decoded : btoa(decoded);

  result.attachments.push({
    name,
    type:      ctLower.split(';')[0].trim(),
    data:      b64,
    contentId: cid || null,
    size:      Math.round(b64.length * 0.75),
  });
}

function parseHeaders(block) {
  const headers = {};
  const lines   = block.replace(/\r\n([ \t])/g, ' ').split('\r\n');
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = decodeRfc2047(line.slice(idx + 1).trim());
  }
  return headers;
}

function splitMultipart(body, boundary) {
  const parts = [], delim = `--${boundary}`, end = `--${boundary}--`;
  let current = [], inPart = false;
  for (const line of body.split('\r\n')) {
    if (line === end)   { if (inPart) parts.push(current.join('\r\n')); break; }
    if (line === delim) { if (inPart) parts.push(current.join('\r\n')); current = []; inPart = true; continue; }
    if (inPart) current.push(line);
  }
  return parts;
}

function decodeQP(str) {
  return str
    .replace(/=\r\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function b64Decode(b64, charset) {
  try { return new TextDecoder(charset, { fatal: false }).decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0))); }
  catch { return atob(b64); }
}

function decodeRfc2047(str) {
  return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, charset, enc, text) => {
    try {
      const bytes = enc.toUpperCase() === 'B'
        ? Uint8Array.from(atob(text), c => c.charCodeAt(0))
        : Uint8Array.from(decodeQP(text.replace(/_/g, ' ')), c => c.charCodeAt(0));
      return new TextDecoder(charset, { fatal: false }).decode(bytes);
    } catch { return text; }
  });
}

function inlineCidImages(html, attachments) {
  return html.replace(/cid:([^"'\s>]+)/gi, (match, cid) => {
    const att = attachments.find(a => a.contentId === cid);
    return att ? `data:${att.type};base64,${att.data}` : match;
  });
}

function isValidEthAddress(addr) {
  return /^0x[0-9a-f]{40}$/i.test(addr);
}

function extractToken(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null;
}

function generateMsgId() {
  return `${Date.now().toString(36)}-${bytesToHex(crypto.getRandomValues(new Uint8Array(8)))}`;
}

function hexToBytes(hex) {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function concatBytes(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0); result.set(b, a.length);
  return result;
}

function arrayBufferToBase64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function jsonResponse(data, status = 200, request, env) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type':  'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...getCorsHeaders(request, env),
    },
  });
}

function corsPreflightResponse(request, env) {
  return new Response(null, {
    status: 204,
    headers: {
      ...getCorsHeaders(request, env),
      'Access-Control-Max-Age': '86400',
    },
  });
}

function getCorsHeaders(request, env) {
  const origin = request?.headers?.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin':      origin,
    'Access-Control-Allow-Methods':     'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary':                             'Origin',
  };
}
