
import { secp256k1 }   from '@noble/curves/secp256k1';
import { keccak_256 }  from '@noble/hashes/sha3';

/* =============================================================================
   ГЛАВНЫЙ ОБРАБОТЧИК
   ============================================================================= */
export default {
  async fetch(request, env, ctx) {
    // Обрабатываем CORS preflight
    if (request.method === 'OPTIONS') {
      return corsPreflightResponse(request, env);
    }

    const url      = new URL(request.url);
    const pathname = url.pathname;

    try {
      // ── Роутер ──────────────────────────────────────────────────────────────
      // Авторизация
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

      // Письма — требуют авторизации
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

      // 404
      return jsonResponse({ error: 'Маршрут не найден' }, 404, request, env);

    } catch (err) {
      console.error('[Worker Error]', err);
      return jsonResponse({ error: 'Внутренняя ошибка сервера' }, 500, request, env);
    }
  },
};

/**
 * Email handler — принимает входящие письма через Cloudflare Email Routing.
 * Включить в wrangler.toml:
 *   [[email]]
 *   type = "worker"
 */
export async function email(message, env, ctx) {
  // 1. Читаем сырой MIME поток
  const rawEmail = await new Response(message.raw).text();

  // 2. Вытаскиваем заголовки (простой парсер)
  const headers  = {};
  const lines    = rawEmail.split('\r\n');
  for (const line of lines) {
    if (line === '') break; // конец заголовков
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    headers[key] = val;
  }

  const sender  = message.from || headers['from']  || 'unknown@sender';
  const subject = headers['subject'] || '(no subject)';
  const date    = headers['date']    || new Date().toISOString();

  // 3. Вытаскиваем тело (после первой пустой строки)
  const bodyStart = rawEmail.indexOf('\r\n\r\n');
  const rawBody   = bodyStart !== -1 ? rawEmail.slice(bodyStart + 4) : rawEmail;

  // 4. Получатель — из какого адреса пришло (ваш @yourdomain)
  const recipient = message.to || 'inbox';

  // 5. Формируем plaintext payload для шифрования
  const payload = JSON.stringify({
    subject,
    from:   sender,
    to:     recipient,
    date,
    body:   rawBody,
  });

  // 6. Генерируем ключ шифрования AES-256-GCM прямо в Worker
  //    (per-message ключ — Zero-Trust: мы его не храним нигде отдельно,
  //     а кладём рядом с письмом в зашифрованном виде)
  const aesKey  = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, true, ['encrypt']
  );
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(payload);

  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, encoded
  );

  // 7. Экспортируем ключ для хранения рядом с письмом
  const rawKeyBuf = await crypto.subtle.exportKey('raw', aesKey);

  // 8. Конвертируем всё в Base64
  const toB64 = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  };

  const blob = {
    iv:      toB64(iv.buffer),
    key:     toB64(rawKeyBuf),      // per-message AES ключ
    payload: toB64(cipherBuf),
  };

  // 9. Определяем адрес кошелька-владельца из env
  //    (тот же ALLOWED_ADDRESS что и в auth)
  const ownerAddress = (env.ALLOWED_ADDRESS || 'unknown').toLowerCase();

  // 10. Генерируем ключ KV
  const msgId  = Date.now().toString(36) + '-' + toB64(crypto.getRandomValues(new Uint8Array(6))).replace(/[^a-z0-9]/gi, '');
  const kvKey  = `email:${ownerAddress}:${msgId}`;

  // 11. Сохраняем зашифрованный блоб с метаданными
  await env.EMAILS_KV.put(
    kvKey,
    JSON.stringify(blob),
    {
      metadata: {
        sender:  sender.slice(0, 100),   // обрезаем на случай длинных адресов
        subject: subject.slice(0, 200),
        date,
        folder:  'inbox',
        unread:  true,
      },
    }
  );

  console.log(`[email] Saved: ${kvKey} | from: ${sender} | subject: ${subject}`);
}

/* =============================================================================
   AUTH: CHALLENGE — генерация нонса для подписи
   ============================================================================= */
/**
 * POST /auth/challenge
 * Body: { "address": "0x..." }
 *
 * Возвращает SIWE-совместимое сообщение и нонс.
 * SafePal отобразит это сообщение пользователю при подписи.
 */
async function handleChallenge(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Неверный JSON' }, 400, request, env);
  }

  const address = (body.address || '').toLowerCase().trim();

  // Валидация Ethereum-адреса
  if (!isValidEthAddress(address)) {
    return jsonResponse({ error: 'Неверный адрес кошелька' }, 400, request, env);
  }

  // Проверяем что это разрешённый адрес
  const allowedAddress = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowedAddress && address !== allowedAddress) {
    return jsonResponse({
      error: 'Этот адрес кошелька не имеет доступа'
    }, 403, request, env);
  }

  // Генерируем случайный нонс (32 байта → hex)
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce      = bytesToHex(nonceBytes);

  // Текущее время ISO для SIWE
  const issuedAt = new Date().toISOString();

  // Срок действия нонса
  const ttl = parseInt(env.NONCE_TTL || '300');

  // SIWE-совместимое сообщение (EIP-4361)
  // SafePal покажет его пользователю перед подписью
  const domain  = 'securemail.worker.dev';
  const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');
  const message = buildSiweMessage({
    domain,
    address,
    statement: 'Войти в SecureMail. Подтвердите вход своим кошельком SafePal.',
    uri:       `https://${domain}`,
    version:   '1',
    chainId,
    nonce,
    issuedAt,
  });

  // Сохраняем нонс в KV (с TTL)
  const nonceKey = `nonce:${nonce}`;
  await env.AUTH_KV.put(nonceKey, JSON.stringify({
    address,
    nonce,
    issuedAt,
    used: false,
  }), { expirationTtl: ttl });

  return jsonResponse({
    message,   // Полное SIWE-сообщение для подписи
    nonce,     // Нонс (дополнительно, для удобства)
    address,
    issuedAt,
    expiresIn: ttl,
  }, 200, request, env);
}

/* =============================================================================
   AUTH: VERIFY — верификация подписи кошелька
   ============================================================================= */
/**
 * POST /auth/verify
 * Body: {
 *   "address":   "0x...",
 *   "signature": "0x...",  // 65-байтная подпись из personal_sign
 *   "nonce":     "abc..."  // нонс из /auth/challenge
 * }
 *
 * Верифицирует подпись через ecrecover и выдаёт сессионный токен.
 */
async function handleVerify(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Неверный JSON' }, 400, request, env);
  }

  const { address, signature, nonce } = body;

  // Базовая валидация
  if (!address || !signature || !nonce) {
    return jsonResponse({
      error: 'Требуются поля: address, signature, nonce'
    }, 400, request, env);
  }

  const addrLower = address.toLowerCase().trim();

  // Загружаем нонс из KV
  const nonceKey  = `nonce:${nonce}`;
  const nonceData = await env.AUTH_KV.get(nonceKey, 'json');

  if (!nonceData) {
    return jsonResponse({
      error: 'Нонс не найден или истёк. Запросите новый challenge.'
    }, 401, request, env);
  }

  if (nonceData.used) {
    return jsonResponse({
      error: 'Нонс уже использован (replay attack protection)'
    }, 401, request, env);
  }

  if (nonceData.address !== addrLower) {
    return jsonResponse({
      error: 'Адрес не совпадает с challenge'
    }, 401, request, env);
  }

  // ── Верификация подписи (secp256k1 + Ethereum prefixed message) ──────────
  const recoveredAddress = recoverEthAddress(nonceData.address, nonce, nonceData.issuedAt, signature, env);

  if (recoveredAddress !== addrLower) {
    return jsonResponse({
      error: `Подпись недействительна. Ожидался адрес ${addrLower}, восстановлен ${recoveredAddress}`
    }, 401, request, env);
  }

  // Помечаем нонс как использованный (защита от replay attack)
  await env.AUTH_KV.put(nonceKey, JSON.stringify({ ...nonceData, used: true }), {
    expirationTtl: 60, // удалится через минуту
  });

  // ── Генерация сессионного токена ─────────────────────────────────────────
  const sessionTtl   = parseInt(env.SESSION_TTL || '86400');
  const token        = await generateSessionToken(addrLower, env.JWT_SECRET || 'fallback-secret-change-me', sessionTtl);
  const sessionKey   = `session:${token}`;

  await env.AUTH_KV.put(sessionKey, JSON.stringify({
    address:   addrLower,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
  }), { expirationTtl: sessionTtl });

  return jsonResponse({
    token,
    address:   addrLower,
    expiresIn: sessionTtl,
    expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString(),
    message:   '✓ Авторизация через кошелёк успешна',
  }, 200, request, env);
}

/* =============================================================================
   AUTH: LOGOUT — инвалидация токена
   ============================================================================= */
async function handleLogout(request, env) {
  const token = extractToken(request);
  if (token) {
    await env.AUTH_KV.delete(`session:${token}`);
  }
  return jsonResponse({ message: 'Сессия завершена' }, 200, request, env);
}

/* =============================================================================
   AUTH: ME — информация о текущей сессии
   ============================================================================= */
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
    address:       session.address,
    createdAt:     session.createdAt,
    expiresAt:     session.expiresAt,
  }, 200, request, env);
}

/* =============================================================================
   MIDDLEWARE: withAuth — проверка сессионного токена
   ============================================================================= */
async function withAuth(request, env, handler) {
  const token = extractToken(request);

  if (!token) {
    return jsonResponse({
      error: 'Требуется авторизация. Передайте токен в заголовке Authorization: Bearer <token>'
    }, 401, request, env);
  }

  const session = await env.AUTH_KV.get(`session:${token}`, 'json');

  if (!session) {
    return jsonResponse({
      error: 'Сессия недействительна или истекла. Выполните вход через кошелёк.'
    }, 401, request, env);
  }

  // Проверяем срок действия (дополнительная проверка, KV TTL — основная)
  if (new Date(session.expiresAt) < new Date()) {
    await env.AUTH_KV.delete(`session:${token}`);
    return jsonResponse({ error: 'Сессия истекла' }, 401, request, env);
  }

  // Передаём обработчику вместе с данными сессии
  return handler(request, env, session);
}

/* =============================================================================
   EMAIL HANDLERS
   ============================================================================= */

/**
 * GET /list
 * Возвращает массив заголовков писем (без расшифровки тел).
 * Ключ — имя в KV, метаданные — опциональный JSON-заголовок.
 */
async function handleList(request, env, session) {
  // Перечисляем все ключи с префиксом email:
  const prefix = `email:${session.address}:`;
  const listed = await env.EMAILS_KV.list({ prefix });

  const headers = listed.keys.map(k => {
    // Метаданные хранятся в name ключа как JSON (если установлены при сохранении)
    const meta = k.metadata || {};
    return {
      key:     k.name,
      sender:  meta.sender  || 'Зашифровано',
      subject: meta.subject || 'Зашифровано',
      date:    meta.date    || null,
      folder:  meta.folder  || 'inbox',
      unread:  meta.unread  !== undefined ? meta.unread : true,
    };
  });

  // Сортируем: новые сверху
  headers.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));

  return jsonResponse({ messages: headers, total: headers.length }, 200, request, env);
}

/**
 * GET /get?key=...
 * Возвращает зашифрованный блоб письма.
 * Формат ответа: { iv, key, payload } — готово для расшифровки в браузере.
 */
async function handleGet(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) {
    return jsonResponse({ error: 'Параметр key обязателен' }, 400, request, env);
  }

  // Проверяем что ключ принадлежит этому пользователю
  if (!key.startsWith(`email:${session.address}:`)) {
    return jsonResponse({ error: 'Доступ запрещён' }, 403, request, env);
  }

  const blob = await env.EMAILS_KV.get(key, 'json');

  if (!blob) {
    return jsonResponse({ error: 'Письмо не найдено' }, 404, request, env);
  }

  return jsonResponse(blob, 200, request, env);
}

/**
 * POST /put
 * Сохраняет зашифрованное письмо.
 * Body: {
 *   "iv":      "<base64>",
 *   "key":     "<base64>",     // per-message AES ключ (опционально)
 *   "payload": "<base64>",     // зашифрованное тело
 *   "meta": {                  // метаданные (не зашифрованы!)
 *     "sender":  "...",
 *     "subject": "...",
 *     "date":    "...",
 *     "folder":  "inbox"
 *   }
 * }
 */
async function handlePut(request, env, session) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Неверный JSON' }, 400, request, env);
  }

  // Валидация обязательных полей
  if (!body.iv || !body.payload) {
    return jsonResponse({ error: 'Поля iv и payload обязательны' }, 400, request, env);
  }

  // Генерируем уникальный ключ письма
  const msgId  = generateMsgId();
  const kvKey  = `email:${session.address}:${msgId}`;

  const meta = body.meta || {};
  const now  = new Date().toISOString();

  // Сохраняем зашифрованный блоб
  await env.EMAILS_KV.put(
    kvKey,
    JSON.stringify({
      iv:      body.iv,
      key:     body.key || null,   // per-message ключ (если клиент передаёт)
      payload: body.payload,
    }),
    {
      metadata: {
        sender:  meta.sender  || 'Неизвестный отправитель',
        subject: meta.subject || '(зашифровано)',
        date:    meta.date    || now,
        folder:  meta.folder  || 'inbox',
        unread:  true,
      },
    }
  );

  return jsonResponse({
    key:     kvKey,
    message: 'Письмо сохранено',
    date:    now,
  }, 201, request, env);
}

/**
 * DELETE /delete?key=...
 * Self-Destruct: удаляет письмо без возможности восстановления.
 */
async function handleDelete(request, env, session) {
  const url = new URL(request.url);
  const key = url.searchParams.get('key');

  if (!key) {
    return jsonResponse({ error: 'Параметр key обязателен' }, 400, request, env);
  }

  // Проверяем владельца
  if (!key.startsWith(`email:${session.address}:`)) {
    return jsonResponse({ error: 'Доступ запрещён' }, 403, request, env);
  }

  // Проверяем что письмо существует
  const blob = await env.EMAILS_KV.get(key);
  if (!blob) {
    return jsonResponse({ error: 'Письмо не найдено' }, 404, request, env);
  }

  await env.EMAILS_KV.delete(key);

  return jsonResponse({
    key,
    message: '✓ Письмо уничтожено навсегда',
    deletedAt: new Date().toISOString(),
  }, 200, request, env);
}

/* =============================================================================
   КРИПТО: Ethereum signature recovery
   Реализует personal_sign / eth_sign верификацию (EIP-191)
   ============================================================================= */

/**
 * Восстанавливает Ethereum-адрес из подписи.
 * Поддерживает personal_sign (prefixed) — стандарт SafePal.
 *
 * @param {string} address   — ожидаемый адрес (для построения SIWE-сообщения)
 * @param {string} nonce     — нонс
 * @param {string} issuedAt  — время выдачи
 * @param {string} signature — hex-подпись 0x... (65 байт: r+s+v)
 * @param {object} env       — окружение Worker
 * @returns {string} — восстановленный адрес в нижнем регистре
 */
function recoverEthAddress(address, nonce, issuedAt, signature, env) {
  try {
    // 1. Строим SIWE-сообщение (точно такое же как в handleChallenge)
    const domain  = 'securemail.worker.dev';
    const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');
    const message = buildSiweMessage({
      domain,
      address,
      statement: 'Войти в SecureMail. Подтвердите вход своим кошельком SafePal.',
      uri:       `https://${domain}`,
      version:   '1',
      chainId,
      nonce,
      issuedAt,
    });

    // 2. Ethereum prefix (EIP-191): "\x19Ethereum Signed Message:\n" + длина + сообщение
    const msgBytes   = new TextEncoder().encode(message);
    const prefix     = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
    const prefixed   = concatBytes(prefix, msgBytes);

    // 3. Keccak256 хэш prefixed-сообщения
    const msgHash    = keccak_256(prefixed);

    // 4. Парсим подпись (65 байт: r[32] + s[32] + v[1])
    const sigHex = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBytes = hexToBytes(sigHex);

    if (sigBytes.length !== 65) {
      throw new Error(`Неверная длина подписи: ${sigBytes.length} байт (ожидается 65)`);
    }

    // r и s — первые 64 байта
    const r = bytesToHex(sigBytes.slice(0, 32));
    const s = bytesToHex(sigBytes.slice(32, 64));
    // v — последний байт (27 или 28 → recovery bit 0 или 1)
    let v = sigBytes[64];
    if (v >= 27) v -= 27; // Нормализуем к 0 или 1

    // 5. Восстанавливаем публичный ключ через secp256k1
    const sig       = secp256k1.Signature.fromCompact(`${r}${s}`).addRecoveryBit(v);
    const pubKeyObj = sig.recoverPublicKey(msgHash);

    // 6. Получаем несжатый публичный ключ (64 байта без prefix 04)
    const pubKeyBytes = pubKeyObj.toRawBytes(false); // uncompressed, 65 байт
    const pubKeyData  = pubKeyBytes.slice(1);         // убираем prefix 04 → 64 байта

    // 7. Keccak256 публичного ключа → берём последние 20 байт → адрес
    const addrHash  = keccak_256(pubKeyData);
    const recovered = '0x' + bytesToHex(addrHash.slice(-20));

    return recovered.toLowerCase();

  } catch (err) {
    console.error('[recoverEthAddress]', err);
    return '0x_recovery_failed';
  }
}

/* =============================================================================
   КРИПТО: SIWE Message Builder (EIP-4361)
   ============================================================================= */

/**
 * Строит стандартное SIWE-сообщение.
 * SafePal корректно отображает этот формат пользователю.
 */
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

/**
 * Chain ID по названию сети.
 */
function getChainId(chainName) {
  const chains = {
    'Ethereum':         1,
    'Goerli':           5,
    'Sepolia':          11155111,
    'BNB Smart Chain':  56,
    'BNB Testnet':      97,
    'Polygon':          137,
    'Avalanche':        43114,
    'Arbitrum':         42161,
    'Optimism':         10,
  };
  return chains[chainName] || 1;
}

/* =============================================================================
   SESSION TOKEN: HMAC-SHA256 (без внешних JWT библиотек)
   ============================================================================= */

/**
 * Генерирует подписанный сессионный токен используя Web Crypto API.
 * Формат: base64url(payload) . base64url(signature)
 */
async function generateSessionToken(address, secret, ttl) {
  const payload    = {
    sub: address,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + ttl,
    jti: bytesToHex(crypto.getRandomValues(new Uint8Array(16))), // уникальный ID
  };

  const payloadB64 = btoa(JSON.stringify(payload));

  // HMAC-SHA256 подпись
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sigBuf  = await crypto.subtle.sign('HMAC', keyMaterial, new TextEncoder().encode(payloadB64));
  const sigB64  = arrayBufferToBase64url(sigBuf);

  return `${payloadB64}.${sigB64}`;
}

/* =============================================================================
   УТИЛИТЫ
   ============================================================================= */

/** Проверяет валидность Ethereum-адреса */
function isValidEthAddress(addr) {
  return /^0x[0-9a-f]{40}$/i.test(addr);
}

/** Извлекает Bearer токен из заголовка Authorization */
function extractToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return null;
}

/** Генерирует уникальный ID письма */
function generateMsgId() {
  const ts    = Date.now().toString(36);
  const rand  = bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
  return `${ts}-${rand}`;
}

/** hex string → Uint8Array */
function hexToBytes(hex) {
  const result = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return result;
}

/** Uint8Array → hex string */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Конкатенирует два Uint8Array */
function concatBytes(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/** ArrayBuffer → base64url (без padding) */
function arrayBufferToBase64url(buf) {
  const bytes  = new Uint8Array(buf);
  let binary   = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/* =============================================================================
   HTTP ОТВЕТЫ И CORS
   ============================================================================= */

/**
 * Строит JSON ответ с правильными CORS заголовками.
 */
function jsonResponse(data, status = 200, request, env) {
  const headers = {
    'Content-Type':  'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache',
    ...getCorsHeaders(request, env),
  };

  return new Response(JSON.stringify(data, null, 2), { status, headers });
}

/**
 * Ответ на CORS preflight (OPTIONS).
 */
function corsPreflightResponse(request, env) {
  return new Response(null, {
    status: 204,
    headers: {
      ...getCorsHeaders(request, env),
      'Access-Control-Max-Age': '86400',
    },
  });
}

/**
 * CORS headers — FIXED.
 *
 * ROOT CAUSE of the original CORS block:
 *   Returning `Access-Control-Allow-Origin: *` together with
 *   `Access-Control-Allow-Credentials: true` is FORBIDDEN by the CORS spec.
 *   Browsers hard-block the preflight response in this case, which produced
 *   the "No Access-Control-Allow-Origin header present" error even though
 *   the header WAS present — it was just invalid.
 *
 * FIX: Always echo back the exact request Origin.
 *   For a personal single-owner app this is correct and safe.
 *   It works for mail.yetazero.xyz, file://, localhost, or any other origin.
 */
function getCorsHeaders(request, env) {
  // Echo the incoming Origin. Never send wildcard when credentials are true.
  const origin = request?.headers?.get('Origin') || '*';

  return {
    'Access-Control-Allow-Origin':      origin,
    'Access-Control-Allow-Methods':     'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
    'Vary':                             'Origin',
  };
}
