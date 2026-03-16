/**
 * =============================================================================
 * ETAMail — Cloudflare Worker
 * Web3 Authentication via SafePal/MetaMask (SIWE — Sign-In with Ethereum)
 * =============================================================================
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return corsPreflightResponse(request, env);
    }

    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      // Auth Routes
      if (pathname === '/auth/challenge' && request.method === 'POST') {
        return await handleChallenge(request, env);
      }
      if (pathname === '/auth/verify' && request.method === 'POST') {
        return await handleVerify(request, env);
      }
      if (pathname === '/auth/logout' && request.method === 'DELETE') {
        return await handleLogout(request, env);
      }
      if (pathname === '/auth/me' && request.method === 'GET') {
        return await handleMe(request, env);
      }

      // Email Routes (Protected)
      if (pathname === '/list' && request.method === 'GET') {
        return await withAuth(request, env, handleList);
      }
      if (pathname === '/get' && request.method === 'GET') {
        return await withAuth(request, env, handleGet);
      }
      if (pathname === '/put' && request.method === 'POST') {
        return await withAuth(request, env, handlePut);
      }
      if (pathname === '/delete' && request.method === 'DELETE') {
        return await withAuth(request, env, handleDelete);
      }

      return jsonResponse({ error: 'Route not found' }, 404, request, env);

    } catch (err) {
      console.error('[Worker Error]', err);
      return jsonResponse({ error: 'Internal Server Error' }, 500, request, env);
    }
  },
};

/** ==========================================
    AUTH HANDLERS
    ========================================== */

async function handleChallenge(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, request, env);
  }

  const address = (body.address || '').toLowerCase().trim();

  if (!isValidEthAddress(address)) {
    return jsonResponse({ error: 'Invalid wallet address' }, 400, request, env);
  }

  const allowedAddress = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowedAddress && address !== allowedAddress) {
    return jsonResponse({
      error: 'This wallet address is not authorized'
    }, 403, request, env);
  }

  // Generate unique nonce
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = bytesToHex(nonceBytes);
  const issuedAt = new Date().toISOString();
  const ttl = parseInt(env.NONCE_TTL || '300');

  const domain = 'etamail.worker.dev';
  const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');
  
  // SIWE Message (Standard EIP-4361)
  const message = buildSiweMessage({
    domain,
    address,
    statement: 'Log in to ETAMail. Confirm access with your SafePal wallet.',
    uri: `https://${domain}`,
    version: '1',
    chainId,
    nonce,
    issuedAt,
  });

  // Store nonce in KV for verification
  const nonceKey = `nonce:${nonce}`;
  await env.AUTH_KV.put(nonceKey, JSON.stringify({
    address,
    nonce,
    issuedAt,
    used: false,
  }), { expirationTtl: ttl });

  return jsonResponse({
    message,
    nonce,
    address,
    issuedAt,
    expiresIn: ttl,
  }, 200, request, env);
}

async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, request, env);
  }

  const { address, signature, nonce } = body;

  if (!address || !signature || !nonce) {
    return jsonResponse({
      error: 'Required fields: address, signature, nonce'
    }, 400, request, env);
  }

  const addrLower = address.toLowerCase().trim();
  const nonceKey = `nonce:${nonce}`;
  const nonceData = await env.AUTH_KV.get(nonceKey, 'json');

  if (!nonceData) {
    return jsonResponse({
      error: 'Nonce not found or expired. Request a new challenge.'
    }, 401, request, env);
  }

  if (nonceData.used) {
    return jsonResponse({
      error: 'Nonce already used (replay attack protection)'
    }, 401, request, env);
  }

  if (nonceData.address !== addrLower) {
    return jsonResponse({
      error: 'Address does not match challenge'
    }, 401, request, env);
  }

  // Cryptographic recovery of the address from signature
  const recoveredAddress = recoverEthAddress(nonceData.address, nonce, nonceData.issuedAt, signature, env);

  if (recoveredAddress !== addrLower) {
    return jsonResponse({
      error: `Signature invalid. Expected ${addrLower}, recovered ${recoveredAddress}`
    }, 401, request, env);
  }

  // Mark nonce as used
  await env.AUTH_KV.put(nonceKey, JSON.stringify({ ...nonceData, used: true }), {
    expirationTtl: 60,
  });

  // Create session token (JWT-like HMAC)
  const sessionTtl = parseInt(env.SESSION_TTL || '86400');
  const token = await generateSessionToken(addrLower, env.JWT_SECRET || 'fallback-secret-change-me', sessionTtl);
  const sessionKey = `session:${token}`;

  await env.AUTH_KV.put(sessionKey, JSON.stringify({
    address: addrLower,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
  }), { expirationTtl: sessionTtl });

  return jsonResponse({
    token,
    address: addrLower,
    expiresIn: sessionTtl,
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
    message: '✓ Wallet authorization successful',
  }, 200, request, env);
}

async function handleLogout(request, env) {
  const token = extractToken(request);
  if (token) {
    await env.AUTH_KV.delete(`session:${token}`);
  }
  return jsonResponse({ message: 'Session terminated' }, 200, request, env);
}

async function handleMe(request, env) {
  const token = extractToken(request);
  if (!token) {
    return jsonResponse({ authenticated: false }, 200, request, env);
  }

  const session = await env.AUTH_KV.get(`session:${token}`, 'json');
  if (!session) {
    return jsonResponse({ authenticated: false }, 200, request, env);
  }

  return jsonResponse({
    authenticated: true,
    address: session.address,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
  }, 200, request, env);
}

/** ==========================================
    AUTH MIDDLEWARE
    ========================================== */

async function withAuth(request, env, handler) {
  const token = extractToken(request);

  if (!token) {
    return jsonResponse({
      error: 'Authorization required. Provide token in Authorization: Bearer <token> header'
    }, 401, request, env);
  }

  const session = await env.AUTH_KV.get(`session:${token}`, 'json');

  if (!session) {
    return jsonResponse({
      error: 'Session invalid or expired. Please sign in with your wallet.'
    }, 401, request, env);
  }

  if (new Date(session.expiresAt) < new Date()) {
    await env.AUTH_KV.delete(`session:${token}`);
    return jsonResponse({ error: 'Session expired' }, 401, request, env);
  }

  return handler(request, env, session);
}

/** ==========================================
    EMAIL HANDLERS
    ========================================== */

async function handleList(request, env, session) {
  const prefix = `email:${session.address}:`;
  const listed = await env.EMAILS_KV.list({ prefix });

  const headers = listed.keys.map(k => {
    const meta = k.metadata || {};
    return {
      key: k.name,
      sender: meta.sender || 'Encrypted',
      subject: meta.subject || 'Encrypted',
      date: meta.date || null,
      folder: meta.folder || 'inbox',
      unread: meta.unread !== undefined ? meta.unread : true,
    };
  });

  headers.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));

  return jsonResponse({ messages: headers, total: headers.length }, 200, request, env);
}

async function handleGet(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) {
    return jsonResponse({ error: 'Key parameter is required' }, 400, request, env);
  }

  if (!key.startsWith(`email:${session.address}:`)) {
    return jsonResponse({ error: 'Access denied' }, 403, request, env);
  }

  const blob = await env.EMAILS_KV.get(key, 'json');

  if (!blob) {
    return jsonResponse({ error: 'Message not found' }, 404, request, env);
  }

  return jsonResponse(blob, 200, request, env);
}

async function handlePut(request, env, session) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON' }, 400, request, env);
  }

  if (!body.iv || !body.payload) {
    return jsonResponse({ error: 'iv and payload fields are required' }, 400, request, env);
  }

  const msgId = generateMsgId();
  const kvKey = `email:${session.address}:${msgId}`;

  const meta = body.meta || {};
  const now = new Date().toISOString();

  await env.EMAILS_KV.put(
    kvKey,
    JSON.stringify({
      iv: body.iv,
      key: body.key || null,
      payload: body.payload,
    }),
    {
      metadata: {
        sender: meta.sender || 'Unknown Sender',
        subject: meta.subject || '(encrypted)',
        date: meta.date || now,
        folder: meta.folder || 'inbox',
        unread: true,
      },
    }
  );

  return jsonResponse({
    key: kvKey,
    message: 'Message saved',
    date: now,
  }, 201, request, env);
}

async function handleDelete(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) {
    return jsonResponse({ error: 'Key parameter is required' }, 400, request, env);
  }

  if (!key.startsWith(`email:${session.address}:`)) {
    return jsonResponse({ error: 'Access denied' }, 403, request, env);
  }

  const blob = await env.EMAILS_KV.get(key);
  if (!blob) {
    return jsonResponse({ error: 'Message not found' }, 404, request, env);
  }

  await env.EMAILS_KV.delete(key);

  return jsonResponse({
    key,
    message: '✓ Message destroyed permanently',
    deletedAt: new Date().toISOString(),
  }, 200, request, env);
}

/** ==========================================
    CRYPTO UTILS
    ========================================== */

function recoverEthAddress(address, nonce, issuedAt, signature, env) {
  try {
    const domain = 'etamail.worker.dev';
    const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');
    const message = buildSiweMessage({
      domain,
      address,
      statement: 'Log in to ETAMail. Confirm access with your SafePal wallet.',
      uri: `https://${domain}`,
      version: '1',
      chainId,
      nonce,
      issuedAt,
    });

    const msgBytes = new TextEncoder().encode(message);
    const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
    const prefixed = concatBytes(prefix, msgBytes);

    const msgHash = keccak_256(prefixed);

    const sigHex = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBytes = hexToBytes(sigHex);

    if (sigBytes.length !== 65) {
      throw new Error(`Invalid signature length: ${sigBytes.length} bytes (expected 65)`);
    }

    const r = bytesToHex(sigBytes.slice(0, 32));
    const s = bytesToHex(sigBytes.slice(32, 64));
    let v = sigBytes[64];
    if (v >= 27) v -= 27;

    const sig = secp256k1.Signature.fromCompact(`${r}${s}`).addRecoveryBit(v);
    const pubKeyObj = sig.recoverPublicKey(msgHash);

    const pubKeyBytes = pubKeyObj.toRawBytes(false);
    const pubKeyData = pubKeyBytes.slice(1);

    const addrHash = keccak_256(pubKeyData);
    const recovered = '0x' + bytesToHex(addrHash.slice(-20));

    return recovered.toLowerCase();

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
    'Ethereum': 1,
    'Goerli': 5,
    'Sepolia': 11155111,
    'BNB Smart Chain': 56,
    'BNB Testnet': 97,
    'Polygon': 137,
    'Avalanche': 43114,
    'Arbitrum': 42161,
    'Optimism': 10,
  };
  return chains[chainName] || 1;
}

async function generateSessionToken(address, secret, ttl) {
  const payload = {
    sub: address,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttl,
    jti: bytesToHex(crypto.getRandomValues(new Uint8Array(16))),
  };

  const payloadB64 = btoa(JSON.stringify(payload));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBuf = await crypto.subtle.sign('HMAC', keyMaterial, new TextEncoder().encode(payloadB64));
  const sigB64 = arrayBufferToBase64url(sigBuf);

  return `${payloadB64}.${sigB64}`;
}

/** ==========================================
    GENERAL HELPERS
    ========================================== */

function isValidEthAddress(addr) {
  return /^0x[0-9a-f]{40}$/i.test(addr);
}

function extractToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

function generateMsgId() {
  const ts = Date.now().toString(36);
  const rand = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
  return `${ts}-${rand}`;
}

function hexToBytes(hex) {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function concatBytes(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function arrayBufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** ==========================================
    RESPONSE HELPERS
    ========================================== */

function jsonResponse(data, status = 200, request, env) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache',
    ...getCorsHeaders(request, env),
  };

  return new Response(JSON.stringify(data, null, 2), { status, headers });
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
  const origin = request?.headers?.get('Origin') || '';
  const allowed = env?.ALLOWED_ORIGINS || '*';

  let allowOrigin = '*';
  if (allowed !== '*') {
    const allowedList = allowed.split(',').map(s => s.trim());
    if (allowedList.includes(origin) || origin === 'null' || !origin) {
      allowOrigin = origin || '*';
    }
  }

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}
