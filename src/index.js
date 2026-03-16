import { secp256k1 }  from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return corsPreflightResponse(request, env);
    const url = new URL(request.url);
    const p   = url.pathname;
    try {
      if (p === '/auth/challenge'     && request.method === 'POST')   return await handleChallenge(request, env);
      if (p === '/auth/verify'        && request.method === 'POST')   return await handleVerify(request, env);
      if (p === '/auth/logout'        && request.method === 'DELETE') return await handleLogout(request, env);
      if (p === '/auth/me'            && request.method === 'GET')    return await handleMe(request, env);
      if (p === '/auth/qr-init'       && request.method === 'POST')   return await handleQrInit(request, env);
      if (p === '/auth/qr-poll'       && request.method === 'GET')    return await handleQrPoll(request, env);
      if (p === '/auth/qr-confirm'    && request.method === 'POST')   return await handleQrConfirm(request, env);
      if (p === '/list'               && request.method === 'GET')    return await withAuth(request, env, handleList);
      if (p === '/get'                && request.method === 'GET')    return await withAuth(request, env, handleGet);
      if (p === '/put'                && request.method === 'POST')   return await withAuth(request, env, handlePut);
      if (p === '/delete'             && request.method === 'DELETE') return await withAuth(request, env, handleDelete);
      if (p === '/send/email'         && request.method === 'POST')   return await withAuth(request, env, handleSendEmail);
      if (p === '/nostr/inbox'        && request.method === 'GET')    return await withAuth(request, env, handleNostrInbox);
      if (p === '/telegram/users'     && request.method === 'GET')    return await withAuth(request, env, handleTelegramUsers);
      if (p === '/telegram/messages'  && request.method === 'GET')    return await withAuth(request, env, handleTelegramMessages);
      if (p === '/telegram/send'      && request.method === 'POST')   return await withAuth(request, env, handleTelegramSend);
      if (p === '/telegram/webhook'   && request.method === 'POST')   return await handleTelegramWebhook(request, env);
      return jsonResponse({ error: 'Not found' }, 404, request, env);
    } catch (err) {
      console.error('[Worker]', err);
      return jsonResponse({ error: 'Internal error' }, 500, request, env);
    }
  },

  async email(message, env, ctx) {
    try {
      const rawBytes = await new Response(message.raw).arrayBuffer();
      const rawText  = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
      const parsed   = parseMime(rawText);
      const sender   = message.from              || parsed.headers['from']  || 'unknown@sender';
      const subject  = parsed.headers['subject'] || '(no subject)';
      const date     = parsed.headers['date']    || new Date().toISOString();
      const to       = message.to                || parsed.headers['to']    || '';
      const body     = parsed.html ? inlineCidImages(parsed.html, parsed.attachments) : (parsed.text || '(empty)');
      const isHtml   = !!parsed.html;
      const payload  = JSON.stringify({
        subject, from: sender, to, date, body, isHtml,
        attachments: parsed.attachments.filter(a => !a.contentId).map(a => ({ name: a.name, type: a.type, data: a.data, size: a.size })),
      });
      const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      const iv     = crypto.getRandomValues(new Uint8Array(12));
      const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload));
      const rawKey = await crypto.subtle.exportKey('raw', aesKey);
      const toB64  = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
      const blob   = { iv: toB64(iv.buffer), key: toB64(rawKey), payload: toB64(cipher) };
      const owner  = (env.ALLOWED_ADDRESS || 'unknown').toLowerCase();
      const msgId  = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0,8)}`;
      const kvKey  = `email:${owner}:${msgId}`;
      await env.EMAILS_KV.put(kvKey, JSON.stringify(blob), {
        metadata: { sender: sender.slice(0,200), subject: subject.slice(0,300), date, folder: 'inbox', unread: true },
      });
      await tgBroadcast(env, `📨 *New email*\n\nFrom: ${escTg(sender)}\nSubject: ${escTg(subject)}\n\n${escTg((parsed.text||'').slice(0,200))}`);
    } catch (err) {
      console.error('[email]', err?.message);
    }
  },
};

async function handleChallenge(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const address = (body.address || '').toLowerCase().trim();
  if (!isValidEthAddress(address)) return jsonResponse({ error: 'Invalid address' }, 400, request, env);
  const allowed = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowed && address !== allowed) return jsonResponse({ error: 'Address not allowed' }, 403, request, env);
  const nonce    = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  const issuedAt = new Date().toISOString();
  const ttl      = parseInt(env.NONCE_TTL || '300');
  const domain   = new URL(request.url).hostname;
  const chainId  = getChainId(env.CHAIN_NAME || 'Ethereum');
  const message  = buildSiweMessage({ domain, address, statement: 'Sign in to ETAMail. This will not trigger a blockchain transaction or cost any gas.', uri: `https://${domain}`, version: '1', chainId, nonce, issuedAt });
  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({ address, nonce, issuedAt, used: false }), { expirationTtl: ttl });
  return jsonResponse({ message, nonce, address, issuedAt, expiresIn: ttl }, 200, request, env);
}

async function handleVerify(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { address, signature, nonce } = body;
  if (!address || !signature || !nonce) return jsonResponse({ error: 'Required: address, signature, nonce' }, 400, request, env);
  const addrLower = address.toLowerCase().trim();
  const nonceData = await env.AUTH_KV.get(`nonce:${nonce}`, 'json');
  if (!nonceData)                return jsonResponse({ error: 'Nonce not found or expired' }, 401, request, env);
  if (nonceData.used)            return jsonResponse({ error: 'Nonce already used' }, 401, request, env);
  if (nonceData.address !== addrLower) return jsonResponse({ error: 'Address mismatch' }, 401, request, env);
  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env, new URL(request.url).hostname);
  if (recovered !== addrLower)   return jsonResponse({ error: `Invalid signature. Got: ${recovered}` }, 401, request, env);
  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({ ...nonceData, used: true }), { expirationTtl: 60 });
  const sessionTtl = parseInt(env.SESSION_TTL || '86400');
  const token      = await generateSessionToken(addrLower, env.JWT_SECRET || 'change-me', sessionTtl);
  await env.AUTH_KV.put(`session:${token}`, JSON.stringify({ address: addrLower, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString() }), { expirationTtl: sessionTtl });
  return jsonResponse({ token, address: addrLower, expiresIn: sessionTtl, expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString() }, 200, request, env);
}

async function handleLogout(request, env) {
  const token = extractToken(request);
  if (token) await env.AUTH_KV.delete(`session:${token}`);
  return jsonResponse({ message: 'Logged out' }, 200, request, env);
}

async function handleMe(request, env) {
  const token   = extractToken(request);
  if (!token) return jsonResponse({ authenticated: false }, 200, request, env);
  const session = await env.AUTH_KV.get(`session:${token}`, 'json');
  if (!session) return jsonResponse({ authenticated: false }, 200, request, env);
  return jsonResponse({ authenticated: true, address: session.address, createdAt: session.createdAt, expiresAt: session.expiresAt }, 200, request, env);
}

async function handleQrInit(request, env) {
  const sessionId = crypto.randomUUID();
  const ttl       = 300;
  await env.AUTH_KV.put(`qr:${sessionId}`, JSON.stringify({ status: 'pending', createdAt: new Date().toISOString() }), { expirationTtl: ttl });
  const origin = request.headers.get('Origin') || `https://${new URL(request.url).hostname}`;
  return jsonResponse({ sessionId, url: `${origin}?qr=${sessionId}`, expiresIn: ttl }, 200, request, env);
}

async function handleQrPoll(request, env) {
  const sessionId = new URL(request.url).searchParams.get('session');
  if (!sessionId) return jsonResponse({ error: 'session required' }, 400, request, env);
  const data = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!data) return jsonResponse({ status: 'expired' }, 200, request, env);
  if (data.status === 'verified') return jsonResponse({ status: 'verified', token: data.token, address: data.address }, 200, request, env);
  return jsonResponse({ status: 'pending' }, 200, request, env);
}

async function handleQrConfirm(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { sessionId, address, signature, nonce } = body;
  if (!sessionId || !address || !signature || !nonce) return jsonResponse({ error: 'Missing fields' }, 400, request, env);
  const qrData = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!qrData || qrData.status !== 'pending') return jsonResponse({ error: 'QR session invalid' }, 409, request, env);
  const addrLower = address.toLowerCase().trim();
  const allowed   = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowed && addrLower !== allowed) return jsonResponse({ error: 'Address not allowed' }, 403, request, env);
  const nonceData = await env.AUTH_KV.get(`nonce:${nonce}`, 'json');
  if (!nonceData || nonceData.used || nonceData.address !== addrLower) return jsonResponse({ error: 'Invalid nonce' }, 401, request, env);
  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env, new URL(request.url).hostname);
  if (recovered !== addrLower) return jsonResponse({ error: 'Invalid signature' }, 401, request, env);
  await env.AUTH_KV.put(`nonce:${nonce}`, JSON.stringify({ ...nonceData, used: true }), { expirationTtl: 60 });
  const sessionTtl = parseInt(env.SESSION_TTL || '86400');
  const token      = await generateSessionToken(addrLower, env.JWT_SECRET || 'change-me', sessionTtl);
  await env.AUTH_KV.put(`session:${token}`, JSON.stringify({ address: addrLower, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + sessionTtl * 1000).toISOString() }), { expirationTtl: sessionTtl });
  await env.AUTH_KV.put(`qr:${sessionId}`, JSON.stringify({ status: 'verified', address: addrLower, token }), { expirationTtl: 60 });
  return jsonResponse({ token, address: addrLower }, 200, request, env);
}

async function withAuth(request, env, handler) {
  const token = extractToken(request);
  if (!token) return jsonResponse({ error: 'Authorization required' }, 401, request, env);
  const session = await env.AUTH_KV.get(`session:${token}`, 'json');
  if (!session || new Date(session.expiresAt) < new Date()) return jsonResponse({ error: 'Session invalid or expired' }, 401, request, env);
  return handler(request, env, session);
}

async function handleList(request, env, session) {
  const prefix = `email:${session.address}:`;
  const listed = await env.EMAILS_KV.list({ prefix });
  const headers = listed.keys.map(k => {
    const m = k.metadata || {};
    return { key: k.name, sender: m.sender || 'Encrypted', subject: m.subject || 'Encrypted', date: m.date || null, folder: m.folder || 'inbox', unread: m.unread !== undefined ? m.unread : true };
  });
  headers.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  return jsonResponse({ messages: headers, total: headers.length }, 200, request, env);
}

async function handleGet(request, env, session) {
  const key = new URL(request.url).searchParams.get('key');
  if (!key) return jsonResponse({ error: 'key required' }, 400, request, env);
  if (!key.startsWith(`email:${session.address}:`)) return jsonResponse({ error: 'Forbidden' }, 403, request, env);
  const blob = await env.EMAILS_KV.get(key, 'json');
  if (!blob) return jsonResponse({ error: 'Not found' }, 404, request, env);
  return jsonResponse(blob, 200, request, env);
}

async function handlePut(request, env, session) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  if (!body.iv || !body.payload) return jsonResponse({ error: 'iv and payload required' }, 400, request, env);
  const meta  = body.meta || {};
  const now   = new Date().toISOString();
  const msgId = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0,8)}`;
  const kvKey = `email:${session.address}:${msgId}`;
  await env.EMAILS_KV.put(kvKey, JSON.stringify({ iv: body.iv, key: body.key || null, payload: body.payload }), {
    metadata: { sender: meta.sender || 'Unknown', subject: meta.subject || '(encrypted)', date: meta.date || now, folder: meta.folder || 'inbox', unread: true },
  });
  return jsonResponse({ key: kvKey, date: now }, 201, request, env);
}

async function handleDelete(request, env, session) {
  const key = new URL(request.url).searchParams.get('key');
  if (!key) return jsonResponse({ error: 'key required' }, 400, request, env);
  if (!key.startsWith(`email:${session.address}:`)) return jsonResponse({ error: 'Forbidden' }, 403, request, env);
  if (!await env.EMAILS_KV.get(key)) return jsonResponse({ error: 'Not found' }, 404, request, env);
  await env.EMAILS_KV.delete(key);
  return jsonResponse({ key, deletedAt: new Date().toISOString() }, 200, request, env);
}

async function handleSendEmail(request, env, session) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { to, subject, text, html, replyTo } = body;
  if (!to || !subject || (!text && !html)) return jsonResponse({ error: 'Required: to, subject, text or html' }, 400, request, env);
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) return jsonResponse({ error: 'RESEND_API_KEY not set. Run: wrangler secret put RESEND_API_KEY' }, 500, request, env);
  // If domain not verified on Resend, use their test sender (only sends to verified account email)
  const configuredFrom = env.MAIL_FROM_ADDRESS || '';
  const fromName       = env.MAIL_FROM_NAME || 'ETAMail';
  const fromAddress    = configuredFrom || 'onboarding@resend.dev';
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from:    `${fromName} <${fromAddress}>`,
        to:      [to],
        subject,
        ...(text ? { text } : {}),
        ...(html ? { html } : {}),
        ...(replyTo ? { reply_to: replyTo } : {}),
      }),
    });
    const resData = await res.json();
    if (!res.ok) {
      if (res.status === 403 && resData.message?.includes('not verified')) {
        return jsonResponse({ error: `Domain "${fromAddress.split('@')[1]}" not verified on Resend.\n\nFix options:\n1. Go to resend.com/domains → Add & verify ${fromAddress.split('@')[1]}\n2. Or set MAIL_FROM_ADDRESS=onboarding@resend.dev in wrangler.toml (only sends to your own email)\n\nAfter verifying domain: wrangler deploy` }, 403, request, env);
      }
      throw new Error(`Resend ${res.status}: ${resData.message || JSON.stringify(resData)}`);
    }
    const payload = JSON.stringify({ subject, from: fromAddress, to, date: new Date().toISOString(), body: text || html, isHtml: !!html });
    const aesKey  = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const cipher  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload));
    const rawKey  = await crypto.subtle.exportKey('raw', aesKey);
    const toB64   = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const msgId   = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0,8)}`;
    await env.EMAILS_KV.put(`email:${session.address}:sent:${msgId}`, JSON.stringify({ iv: toB64(iv.buffer), key: toB64(rawKey), payload: toB64(cipher) }), {
      metadata: { sender: fromAddress, subject, date: new Date().toISOString(), folder: 'sent', unread: false },
    });
    return jsonResponse({ ok: true, message: `Email sent to ${to}`, id: resData.id }, 200, request, env);
  } catch (err) {
    return jsonResponse({ error: err.message }, 500, request, env);
  }
}

async function handleNostrInbox(request, env, session) {
  const url    = new URL(request.url);
  const pubkey = url.searchParams.get('pubkey');
  const limit  = parseInt(url.searchParams.get('limit') || '20');
  if (!pubkey) return jsonResponse({ error: 'pubkey required' }, 400, request, env);
  try {
    const res  = await fetch(`https://api.nostr.band/v0/search/notes?q=${encodeURIComponent(`#${pubkey}`)}&limit=${limit}`, { headers: { 'Accept': 'application/json' } });
    if (!res.ok) throw new Error(`nostr.band HTTP ${res.status}`);
    const data  = await res.json();
    const items = (data.notes || []).map(n => ({ id: n.id, pubkey: n.pubkey, content: n.content, createdAt: new Date(n.created_at * 1000).toISOString(), kind: n.kind }));
    return jsonResponse({ events: items, count: items.length }, 200, request, env);
  } catch (err) {
    return jsonResponse({ error: err.message, events: [] }, 200, request, env);
  }
}

async function handleTelegramUsers(request, env, session) {
  const listed = await env.AUTH_KV.list({ prefix: 'tg:chat:' });
  const users  = [];
  for (const key of listed.keys) {
    const data = await env.AUTH_KV.get(key.name, 'json');
    if (data?.user?.chatId) {
      const last = data.messages?.[data.messages.length - 1] || null;
      users.push({ chatId: data.user.chatId, username: data.user.username || '', firstName: data.user.firstName || '', lastName: data.user.lastName || '', linkedAt: data.user.linkedAt || '', lastMessage: last, unread: data.unread || 0 });
    }
  }
  users.sort((a, b) => (b.lastMessage?.ts || 0) - (a.lastMessage?.ts || 0));
  return jsonResponse({ users }, 200, request, env);
}

async function handleTelegramMessages(request, env, session) {
  const chatId = new URL(request.url).searchParams.get('chatId');
  if (!chatId) return jsonResponse({ error: 'chatId required' }, 400, request, env);
  const data = await env.AUTH_KV.get(`tg:chat:${chatId}`, 'json');
  if (data && data.unread > 0) {
    data.unread = 0;
    await env.AUTH_KV.put(`tg:chat:${chatId}`, JSON.stringify(data));
  }
  return jsonResponse({ messages: data?.messages || [], user: data?.user || { chatId } }, 200, request, env);
}

async function handleTelegramSend(request, env, session) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { chatId, text } = body;
  if (!chatId || !text) return jsonResponse({ error: 'chatId and text required' }, 400, request, env);
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) return jsonResponse({ error: 'Telegram not configured' }, 500, request, env);
  await tgSend(token, chatId, text);
  const key  = `tg:chat:${chatId}`;
  const data = await env.AUTH_KV.get(key, 'json') || { user: { chatId }, messages: [], unread: 0 };
  data.messages.push({ text, dir: 'out', ts: Date.now() });
  if (data.messages.length > 200) data.messages = data.messages.slice(-200);
  await env.AUTH_KV.put(key, JSON.stringify(data));
  return jsonResponse({ ok: true }, 200, request, env);
}

async function handleTelegramWebhook(request, env) {
  let update;
  try { update = await request.json(); } catch { return new Response('ok'); }
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) return new Response('ok');
  const msg     = update.message || update.edited_message;
  const cbQuery = update.callback_query;
  if (msg)     await processTgMessage(msg, token, env);
  if (cbQuery) await processTgCallback(cbQuery, token, env);
  return new Response('ok', { status: 200 });
}

async function processTgMessage(msg, token, env) {
  const chatId  = msg.chat.id;
  const text    = (msg.text || '').trim();
  const allowed = env.TELEGRAM_ALLOWED_CHAT;
  if (allowed && String(chatId) !== String(allowed)) {
    await tgSend(token, chatId, '🚫 Unauthorized.');
    return;
  }

  const key      = `tg:chat:${chatId}`;
  const chatData = await env.AUTH_KV.get(key, 'json') || { user: {}, messages: [], unread: 0 };
  chatData.user  = { chatId, username: msg.from?.username || chatData.user?.username || '', firstName: msg.from?.first_name || chatData.user?.firstName || '', lastName: msg.from?.last_name || chatData.user?.lastName || '', linkedAt: chatData.user?.linkedAt || '' };

  const stateData = await env.AUTH_KV.get(`tg:state:${chatId}`, 'json');

  const isCommand = text.startsWith('/');
  if (!isCommand) {
    chatData.messages.push({ text, dir: 'in', ts: (msg.date || Math.floor(Date.now()/1000)) * 1000 });
    if (chatData.messages.length > 200) chatData.messages = chatData.messages.slice(-200);
    chatData.unread = (chatData.unread || 0) + 1;
    await env.AUTH_KV.put(key, JSON.stringify(chatData));
  }

  if (stateData?.action === 'awaiting_reply_body') {
    await env.AUTH_KV.delete(`tg:state:${chatId}`);
    await sendEmailResend(env, { to: stateData.to, subject: stateData.subject, text });
    await tgSend(token, chatId, `✅ Reply sent to ${stateData.to}`);
    return;
  }
  if (stateData?.action === 'awaiting_compose_to') {
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_subject', to: text }), { expirationTtl: 300 });
    await tgSend(token, chatId, `📝 Subject:`);
    return;
  }
  if (stateData?.action === 'awaiting_compose_subject') {
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_body', to: stateData.to, subject: text }), { expirationTtl: 300 });
    await tgSend(token, chatId, `✏️ Message body:`);
    return;
  }
  if (stateData?.action === 'awaiting_compose_body') {
    await env.AUTH_KV.delete(`tg:state:${chatId}`);
    await sendEmailResend(env, { to: stateData.to, subject: stateData.subject, text });
    await tgSend(token, chatId, `✅ Email sent to ${stateData.to}`);
    return;
  }

  if (!isCommand) return;

  if (text === '/start' || text === '/help') {
    await tgSend(token, chatId, `🔐 *ETAMail*\n\n/inbox — last 5 emails\n/unread — unread\n/compose — write email\n/stats — stats\n/link — link this chat\n/cancel — cancel`, { parse_mode: 'Markdown' });
    return;
  }
  if (text === '/cancel') { await env.AUTH_KV.delete(`tg:state:${chatId}`); await tgSend(token, chatId, '✅ Cancelled.'); return; }
  if (text === '/compose') { await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_to' }), { expirationTtl: 300 }); await tgSend(token, chatId, '📧 To (email):'); return; }
  if (text === '/link') {
    chatData.user.linkedAt = new Date().toISOString();
    await env.AUTH_KV.put(key, JSON.stringify(chatData));
    await tgSend(token, chatId, `✅ Chat linked! Messages from ETAMail will appear here.`);
    return;
  }
  if (text === '/inbox' || text === '/unread') {
    const onlyUnread = text === '/unread';
    const owner      = (env.ALLOWED_ADDRESS || '').toLowerCase();
    const listed     = await env.EMAILS_KV.list({ prefix: `email:${owner}:`, limit: 50 });
    let emails       = listed.keys.filter(k => !k.name.includes(':sent:')).map(k => ({ key: k.name, sender: k.metadata?.sender || '?', subject: k.metadata?.subject || '(no subject)', date: k.metadata?.date || '', unread: k.metadata?.unread !== false })).sort((a,b) => new Date(b.date)-new Date(a.date));
    if (onlyUnread) emails = emails.filter(e => e.unread);
    if (!emails.length) { await tgSend(token, chatId, onlyUnread ? '📭 No unread.' : '📭 Empty.'); return; }
    const lines    = emails.slice(0,5).map((e,i) => `${i+1}. ${e.unread?'🔵':'⚪'} *${escTg(e.subject)}*\n   ${escTg(e.sender)}`).join('\n\n');
    const keyboard = { inline_keyboard: emails.slice(0,5).map((e,i) => [{ text: `↩️ Reply ${i+1}`, callback_data: `reply:${i}:${e.sender.slice(0,20)}:${e.subject.slice(0,20)}` }]) };
    await env.AUTH_KV.put(`tg:inbox:${chatId}`, JSON.stringify(emails.slice(0,5).map(e => ({ sender: e.sender, subject: e.subject }))), { expirationTtl: 300 });
    await tgSend(token, chatId, `📬 *(${emails.length} total)*:\n\n${lines}`, { parse_mode: 'Markdown', reply_markup: JSON.stringify(keyboard) });
    return;
  }
  if (text === '/stats') {
    const owner  = (env.ALLOWED_ADDRESS || '').toLowerCase();
    const listed = await env.EMAILS_KV.list({ prefix: `email:${owner}:`, limit: 1000 });
    const total  = listed.keys.filter(k => !k.name.includes(':sent:')).length;
    const sent   = listed.keys.filter(k => k.name.includes(':sent:')).length;
    const unread = listed.keys.filter(k => !k.name.includes(':sent:') && k.metadata?.unread !== false).length;
    await tgSend(token, chatId, `📊 *Stats*\n\n📥 Inbox: ${total}\n📤 Sent: ${sent}\n🔵 Unread: ${unread}`, { parse_mode: 'Markdown' });
    return;
  }
  await tgSend(token, chatId, '❓ Unknown command. /help');
}

async function processTgCallback(cb, token, env) {
  const chatId = cb.message?.chat?.id;
  const data   = cb.data || '';
  await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_query_id: cb.id }) });
  if (data.startsWith('reply:')) {
    const parts   = data.split(':');
    const idx     = parseInt(parts[1]);
    const inbox   = await env.AUTH_KV.get(`tg:inbox:${chatId}`, 'json') || [];
    const email   = inbox[idx];
    if (!email) { await tgSend(token, chatId, '❌ Email not found. Use /inbox again.'); return; }
    const subject = email.subject.startsWith('Re:') ? email.subject : `Re: ${email.subject}`;
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_reply_body', to: email.sender, subject }), { expirationTtl: 300 });
    await tgSend(token, chatId, `↩️ Replying to *${escTg(email.sender)}*\nSubject: *${escTg(subject)}*\n\nWrite your reply:`, { parse_mode: 'Markdown' });
  }
}

async function sendEmailResend(env, { to, subject, text }) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const fromAddress = env.MAIL_FROM_ADDRESS || 'mail@yetazero.xyz';
  const fromName    = env.MAIL_FROM_NAME    || 'ETAMail';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: `${fromName} <${fromAddress}>`, to: [to], subject, text }),
  });
  if (!res.ok) throw new Error(`Resend ${res.status}`);
}

async function tgBroadcast(env, text) {
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) return;
  const chats = await env.AUTH_KV.list({ prefix: 'tg:chat:' });
  for (const key of chats.keys) {
    const data = await env.AUTH_KV.get(key.name, 'json');
    if (data?.user?.chatId && data.user.linkedAt) {
      await tgSend(token, data.user.chatId, text, { parse_mode: 'Markdown' }).catch(() => {});
    }
  }
}

async function tgSend(token, chatId, text, extra = {}) {
  return fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text, ...extra }),
  });
}

function escTg(str) { return (str || '').replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&').slice(0, 200); }

function recoverEthAddress(address, nonce, issuedAt, signature, env, hostname) {
  try {
    const domain   = hostname || 'worker.yetazero.xyz';
    const chainId  = getChainId(env.CHAIN_NAME || 'Ethereum');
    const message  = buildSiweMessage({ domain, address, statement: 'Sign in to ETAMail. This will not trigger a blockchain transaction or cost any gas.', uri: `https://${domain}`, version: '1', chainId, nonce, issuedAt });
    const msgBytes = new TextEncoder().encode(message);
    const prefix   = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
    const prefixed = concatBytes(prefix, msgBytes);
    const msgHash  = keccak_256(prefixed);
    const sigHex   = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBytes = hexToBytes(sigHex);
    if (sigBytes.length !== 65) throw new Error(`Bad sig length: ${sigBytes.length}`);
    const r = bytesToHex(sigBytes.slice(0, 32)), s = bytesToHex(sigBytes.slice(32, 64));
    let v = sigBytes[64]; if (v >= 27) v -= 27;
    const sig        = secp256k1.Signature.fromCompact(`${r}${s}`).addRecoveryBit(v);
    const pubKeyData = sig.recoverPublicKey(msgHash).toRawBytes(false).slice(1);
    const addrHash   = keccak_256(pubKeyData);
    return ('0x' + bytesToHex(addrHash.slice(-20))).toLowerCase();
  } catch (err) {
    console.error('[recover]', err);
    return '0x_failed';
  }
}

function buildSiweMessage({ domain, address, statement, uri, version, chainId, nonce, issuedAt }) {
  return [`${domain} wants you to sign in with your Ethereum account:`, address, '', statement, '', `URI: ${uri}`, `Version: ${version}`, `Chain ID: ${chainId}`, `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join('\n');
}

function getChainId(name) { return ({ 'Ethereum':1,'BNB Smart Chain':56,'Polygon':137,'Avalanche':43114,'Arbitrum':42161,'Optimism':10 })[name] || 1; }

async function generateSessionToken(address, secret, ttl) {
  const payload    = { sub: address, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+ttl, jti: bytesToHex(crypto.getRandomValues(new Uint8Array(16))) };
  const payloadB64 = btoa(JSON.stringify(payload));
  const km         = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf     = await crypto.subtle.sign('HMAC', km, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
}

function isValidEthAddress(a) { return /^0x[0-9a-f]{40}$/i.test(a); }
function extractToken(r) { const a = r.headers.get('Authorization')||''; return a.startsWith('Bearer ') ? a.slice(7).trim() : null; }
function hexToBytes(hex) { const r=new Uint8Array(hex.length/2); for(let i=0;i<hex.length;i+=2)r[i/2]=parseInt(hex.slice(i,i+2),16); return r; }
function bytesToHex(b)   { return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''); }
function concatBytes(a,b){ const r=new Uint8Array(a.length+b.length); r.set(a,0); r.set(b,a.length); return r; }

function parseMime(raw) { const result={headers:{},text:'',html:'',attachments:[],_root:true}; parsePart(raw,result); return result; }
function parsePart(raw,result) {
  const split=raw.indexOf('\r\n\r\n'),hdrBlock=split!==-1?raw.slice(0,split):raw,body=split!==-1?raw.slice(split+4):'';
  const headers=parseHeaders(hdrBlock);
  if(result._root){result.headers={...result.headers,...headers};delete result._root;}
  const ct=headers['content-type']||'text/plain',ctLower=ct.toLowerCase(),enc=(headers['content-transfer-encoding']||'').toLowerCase().trim();
  const cid=(headers['content-id']||'').replace(/[<>]/g,'').trim(),disp=(headers['content-disposition']||'').toLowerCase(),isAttach=disp.startsWith('attachment');
  if(ctLower.startsWith('multipart/')){const bm=ct.match(/boundary\s*=\s*"?([^";]+)"?/i);if(!bm)return;for(const part of splitMultipart(body,bm[1].trim()))parsePart(part,result);return;}
  let decoded=enc==='base64'?body.replace(/\s/g,''):enc==='quoted-printable'?decodeQP(body):body;
  const csm=ct.match(/charset\s*=\s*"?([^";]+)"?/i),charset=csm?csm[1].trim():'utf-8';
  if(ctLower.startsWith('text/html')&&!isAttach){result.html+=enc==='base64'?b64Decode(decoded,charset):decoded;return;}
  if(ctLower.startsWith('text/plain')&&!isAttach){result.text+=enc==='base64'?b64Decode(decoded,charset):decoded;return;}
  const namem=ct.match(/name\s*=\s*"?([^";]+)"?/i)||disp.match(/filename\s*=\s*"?([^";]+)"?/i);
  const name=namem?namem[1].trim():(cid||'attachment'),b64=enc==='base64'?decoded:btoa(decoded);
  result.attachments.push({name,type:ctLower.split(';')[0].trim(),data:b64,contentId:cid||null,size:Math.round(b64.length*0.75)});
}
function parseHeaders(block) {
  const headers={};
  for(const line of block.replace(/\r\n([ \t])/g,' ').split('\r\n')){const idx=line.indexOf(':');if(idx===-1)continue;headers[line.slice(0,idx).trim().toLowerCase()]=decodeRfc2047(line.slice(idx+1).trim());}
  return headers;
}
function splitMultipart(body,boundary) {
  const parts=[],delim=`--${boundary}`,end=`--${boundary}--`;let current=[],inPart=false;
  for(const line of body.split('\r\n')){if(line===end){if(inPart)parts.push(current.join('\r\n'));break;}if(line===delim){if(inPart)parts.push(current.join('\r\n'));current=[];inPart=true;continue;}if(inPart)current.push(line);}
  return parts;
}
function decodeQP(s)           { return s.replace(/=\r\n/g,'').replace(/=([0-9A-Fa-f]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16))); }
function b64Decode(b64,charset){ try{return new TextDecoder(charset,{fatal:false}).decode(Uint8Array.from(atob(b64),c=>c.charCodeAt(0)));}catch{return atob(b64);} }
function decodeRfc2047(str)    { return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g,(_,charset,enc,text)=>{try{const bytes=enc.toUpperCase()==='B'?Uint8Array.from(atob(text),c=>c.charCodeAt(0)):Uint8Array.from(decodeQP(text.replace(/_/g,' ')),c=>c.charCodeAt(0));return new TextDecoder(charset,{fatal:false}).decode(bytes);}catch{return text;}}); }
function inlineCidImages(html,attachments){ return html.replace(/cid:([^"'\s>]+)/gi,(match,cid)=>{const att=attachments.find(a=>a.contentId===cid);return att?`data:${att.type};base64,${att.data}`:match;}); }

function jsonResponse(data,status=200,request,env){return new Response(JSON.stringify(data,null,2),{status,headers:{'Content-Type':'application/json;charset=utf-8','Cache-Control':'no-store',...getCorsHeaders(request,env)}});}
function corsPreflightResponse(request,env){return new Response(null,{status:204,headers:{...getCorsHeaders(request,env),'Access-Control-Max-Age':'86400'}});}
function getCorsHeaders(request,env){const origin=request?.headers?.get('Origin')||'*';return{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'GET, POST, DELETE, OPTIONS','Access-Control-Allow-Headers':'Content-Type, Authorization','Access-Control-Allow-Credentials':'true','Vary':'Origin'};}
