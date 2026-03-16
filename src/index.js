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
      await tgForwardEmail(env, { kvKey, sender, subject, date, body: parsed.text || '' });
    } catch (err) {
      console.error('[email handler]', err?.message);
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
  const reqUrl   = new URL(request.url);
  const domain   = reqUrl.hostname;
  const chainId  = getChainId(env.CHAIN_NAME || 'Ethereum');
  const message  = buildSiweMessage({ domain, address, statement: 'Sign in to ETAMail. This request will not trigger a blockchain transaction or cost any gas.', uri: `https://${domain}`, version: '1', chainId, nonce, issuedAt });
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
  if (!nonceData)              return jsonResponse({ error: 'Nonce not found or expired' }, 401, request, env);
  if (nonceData.used)          return jsonResponse({ error: 'Nonce already used' }, 401, request, env);
  if (nonceData.address !== addrLower) return jsonResponse({ error: 'Address mismatch' }, 401, request, env);
  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env);
  if (recovered !== addrLower) return jsonResponse({ error: `Invalid signature. Recovered: ${recovered}` }, 401, request, env);
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
  await env.AUTH_KV.put(`qr:${sessionId}`, JSON.stringify({ status: 'pending', createdAt: new Date().toISOString(), address: null, token: null }), { expirationTtl: ttl });
  const origin = request.headers.get('Origin') || `https://${new URL(request.url).hostname}`;
  return jsonResponse({ sessionId, url: `${origin}?qr=${sessionId}`, expiresIn: ttl }, 200, request, env);
}

async function handleQrPoll(request, env) {
  const sessionId = new URL(request.url).searchParams.get('session');
  if (!sessionId) return jsonResponse({ error: 'session param required' }, 400, request, env);
  const qrData = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!qrData) return jsonResponse({ status: 'expired' }, 200, request, env);
  if (qrData.status === 'verified') return jsonResponse({ status: 'verified', token: qrData.token, address: qrData.address }, 200, request, env);
  return jsonResponse({ status: 'pending' }, 200, request, env);
}

async function handleQrConfirm(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { sessionId, address, signature, nonce } = body;
  if (!sessionId || !address || !signature || !nonce) return jsonResponse({ error: 'Missing fields' }, 400, request, env);
  const qrData = await env.AUTH_KV.get(`qr:${sessionId}`, 'json');
  if (!qrData)                     return jsonResponse({ error: 'QR session not found' }, 404, request, env);
  if (qrData.status !== 'pending') return jsonResponse({ error: 'QR session already used' }, 409, request, env);
  const addrLower = address.toLowerCase().trim();
  const allowed   = (env.ALLOWED_ADDRESS || '').toLowerCase().trim();
  if (allowed && addrLower !== allowed) return jsonResponse({ error: 'Address not allowed' }, 403, request, env);
  const nonceData = await env.AUTH_KV.get(`nonce:${nonce}`, 'json');
  if (!nonceData || nonceData.used || nonceData.address !== addrLower) return jsonResponse({ error: 'Invalid nonce' }, 401, request, env);
  const recovered = recoverEthAddress(addrLower, nonce, nonceData.issuedAt, signature, env);
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
  if (!session) return jsonResponse({ error: 'Session invalid or expired' }, 401, request, env);
  if (new Date(session.expiresAt) < new Date()) { await env.AUTH_KV.delete(`session:${token}`); return jsonResponse({ error: 'Session expired' }, 401, request, env); }
  return handler(request, env, session);
}

async function handleList(request, env, session) {
  const prefix = `email:${session.address}:`;
  const listed = await env.EMAILS_KV.list({ prefix });
  const headers = listed.keys.map(k => {
    const meta = k.metadata || {};
    return { key: k.name, sender: meta.sender || 'Encrypted', subject: meta.subject || 'Encrypted', date: meta.date || null, folder: meta.folder || 'inbox', unread: meta.unread !== undefined ? meta.unread : true };
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
  const url = new URL(request.url);
  const key = url.searchParams.get('key');
  if (!key) return jsonResponse({ error: 'key param required' }, 400, request, env);
  if (!key.startsWith(`email:${session.address}:`)) return jsonResponse({ error: 'Forbidden' }, 403, request, env);
  const blob = await env.EMAILS_KV.get(key);
  if (!blob) return jsonResponse({ error: 'Not found' }, 404, request, env);
  await env.EMAILS_KV.delete(key);
  return jsonResponse({ key, deletedAt: new Date().toISOString() }, 200, request, env);
}

async function handleSendEmail(request, env, session) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: 'Invalid JSON' }, 400, request, env); }
  const { to, subject, text, html, replyTo } = body;
  if (!to || !subject || (!text && !html)) return jsonResponse({ error: 'Required: to, subject, text or html' }, 400, request, env);
  const fromAddress = env.MAIL_FROM_ADDRESS || `mail@${new URL(request.url).hostname}`;
  const fromName    = env.MAIL_FROM_NAME    || 'ETAMail';
  try {
    const res = await fetch('https://api.mailchannels.net/tx/v1/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }], ...(replyTo ? { reply_to: { email: replyTo } } : {}) }],
        from: { email: fromAddress, name: fromName },
        subject,
        content: [...(text ? [{ type: 'text/plain', value: text }] : []), ...(html ? [{ type: 'text/html', value: html }] : [])],
      }),
    });
    if (!res.ok && res.status !== 202) throw new Error(`MailChannels ${res.status}: ${await res.text()}`);
    const payload  = JSON.stringify({ subject, from: fromAddress, to, date: new Date().toISOString(), body: text || html, isHtml: !!html });
    const aesKey   = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const iv       = crypto.getRandomValues(new Uint8Array(12));
    const cipher   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload));
    const rawKey   = await crypto.subtle.exportKey('raw', aesKey);
    const toB64    = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const msgId    = `${Date.now().toString(36)}-${crypto.randomUUID().slice(0,8)}`;
    await env.EMAILS_KV.put(`email:${session.address}:sent:${msgId}`, JSON.stringify({ iv: toB64(iv.buffer), key: toB64(rawKey), payload: toB64(cipher) }), {
      metadata: { sender: fromAddress, subject, date: new Date().toISOString(), folder: 'sent', unread: false },
    });
    return jsonResponse({ ok: true, message: `Email sent to ${to}` }, 200, request, env);
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

  const stateData = await env.AUTH_KV.get(`tg:state:${chatId}`, 'json');

  if (stateData?.action === 'awaiting_reply_body') {
    await env.AUTH_KV.delete(`tg:state:${chatId}`);
    try {
      await fetch('https://api.mailchannels.net/tx/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: stateData.to }] }],
          from: { email: env.MAIL_FROM_ADDRESS || 'mail@yetazero.xyz', name: env.MAIL_FROM_NAME || 'ETAMail' },
          subject: stateData.subject,
          content: [{ type: 'text/plain', value: text }],
        }),
      });
      await tgSend(token, chatId, `✅ Reply sent to ${stateData.to}`);
    } catch (err) {
      await tgSend(token, chatId, `❌ Send failed: ${err.message}`);
    }
    return;
  }

  if (stateData?.action === 'awaiting_compose_to') {
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_subject', to: text }), { expirationTtl: 300 });
    await tgSend(token, chatId, `📝 Subject for email to ${text}:`);
    return;
  }

  if (stateData?.action === 'awaiting_compose_subject') {
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_body', to: stateData.to, subject: text }), { expirationTtl: 300 });
    await tgSend(token, chatId, `✏️ Write your message body:`);
    return;
  }

  if (stateData?.action === 'awaiting_compose_body') {
    await env.AUTH_KV.delete(`tg:state:${chatId}`);
    try {
      await fetch('https://api.mailchannels.net/tx/v1/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: stateData.to }] }],
          from: { email: env.MAIL_FROM_ADDRESS || 'mail@yetazero.xyz', name: env.MAIL_FROM_NAME || 'ETAMail' },
          subject: stateData.subject,
          content: [{ type: 'text/plain', value: text }],
        }),
      });
      await tgSend(token, chatId, `✅ Email sent!\nTo: ${stateData.to}\nSubject: ${stateData.subject}`);
    } catch (err) {
      await tgSend(token, chatId, `❌ Send failed: ${err.message}`);
    }
    return;
  }

  if (text === '/start' || text === '/help') {
    await tgSend(token, chatId,
      `🔐 *ETAMail*\n\n/inbox — last 5 emails\n/unread — unread only\n/compose — write new email\n/stats — storage info\n/link — link this chat\n/cancel — cancel current action`,
      { parse_mode: 'Markdown' }
    );
    return;
  }

  if (text === '/cancel') {
    await env.AUTH_KV.delete(`tg:state:${chatId}`);
    await tgSend(token, chatId, '✅ Cancelled.');
    return;
  }

  if (text === '/compose') {
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_compose_to' }), { expirationTtl: 300 });
    await tgSend(token, chatId, '📧 To (email address):');
    return;
  }

  if (text === '/inbox' || text === '/unread') {
    const onlyUnread = text === '/unread';
    const owner      = (env.ALLOWED_ADDRESS || '').toLowerCase();
    const listed     = await env.EMAILS_KV.list({ prefix: `email:${owner}:`, limit: 50 });
    let emails = listed.keys
      .filter(k => !k.name.includes(':sent:'))
      .map(k => ({ key: k.name, sender: k.metadata?.sender || '?', subject: k.metadata?.subject || '(no subject)', date: k.metadata?.date || '', unread: k.metadata?.unread !== false }))
      .sort((a, b) => new Date(b.date) - new Date(a.date));
    if (onlyUnread) emails = emails.filter(e => e.unread);
    if (!emails.length) { await tgSend(token, chatId, onlyUnread ? '📭 No unread.' : '📭 Inbox empty.'); return; }
    const lines = emails.slice(0, 5).map((e, i) =>
      `${i+1}\\. ${e.unread ? '🔵' : '⚪'} *${escTg(e.subject)}*\n   From: ${escTg(e.sender)}`
    ).join('\n\n');
    const keyboard = {
      inline_keyboard: emails.slice(0, 5).map((e, i) => [{ text: `↩️ Reply ${i+1}`, callback_data: `reply:${e.key}:${e.sender}:${e.subject}` }])
    };
    await tgSend(token, chatId, `📬 *${onlyUnread ? 'Unread' : 'Inbox'}* (${emails.length}):\n\n${lines}`, { parse_mode: 'MarkdownV2', reply_markup: JSON.stringify(keyboard) });
    return;
  }

  if (text === '/stats') {
    const owner  = (env.ALLOWED_ADDRESS || '').toLowerCase();
    const listed = await env.EMAILS_KV.list({ prefix: `email:${owner}:`, limit: 1000 });
    const total  = listed.keys.filter(k => !k.name.includes(':sent:')).length;
    const sent   = listed.keys.filter(k => k.name.includes(':sent:')).length;
    const unread = listed.keys.filter(k => !k.name.includes(':sent:') && k.metadata?.unread !== false).length;
    await tgSend(token, chatId, `📊 *ETAMail Stats*\n\n📥 Inbox: ${total}\n📤 Sent: ${sent}\n🔵 Unread: ${unread}`, { parse_mode: 'Markdown' });
    return;
  }

  if (text === '/link') {
    await env.AUTH_KV.put(`tg:chat:${chatId}`, JSON.stringify({ chatId, linkedAt: new Date().toISOString() }));
    await tgSend(token, chatId, `✅ Chat linked. New emails will appear here with reply buttons.`);
    return;
  }

  await tgSend(token, chatId, '❓ Unknown command. Use /help');
}

async function processTgCallback(cb, token, env) {
  const chatId = cb.message?.chat?.id;
  const data   = cb.data || '';
  await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: cb.id }),
  });
  if (data.startsWith('reply:')) {
    const parts   = data.split(':');
    const to      = parts[2] || '';
    const subject = parts.slice(3).join(':') || '';
    const replySubject = subject.startsWith('Re:') ? subject : `Re: ${subject}`;
    await env.AUTH_KV.put(`tg:state:${chatId}`, JSON.stringify({ action: 'awaiting_reply_body', to, subject: replySubject }), { expirationTtl: 300 });
    await tgSend(token, chatId, `↩️ Replying to *${escTg(to)}*\nSubject: *${escTg(replySubject)}*\n\nWrite your reply:`, { parse_mode: 'Markdown' });
  }
  if (data.startsWith('delete:')) {
    const key   = data.slice(7);
    const owner = (env.ALLOWED_ADDRESS || '').toLowerCase();
    if (key.startsWith(`email:${owner}:`)) {
      await env.EMAILS_KV.delete(key);
      await tgSend(token, chatId, '🗑 Email deleted.');
    }
  }
}

async function tgForwardEmail(env, { kvKey, sender, subject, date, body }) {
  const token = env.TELEGRAM_BOT_TOKEN;
  if (!token) return;
  const chats = await env.AUTH_KV.list({ prefix: 'tg:chat:' });
  const preview = (body || '').replace(/\s+/g, ' ').slice(0, 200);
  const msgText = `📨 *New Email*\n\nFrom: ${escTg(sender)}\nSubject: ${escTg(subject)}\n\n${escTg(preview)}${preview.length >= 200 ? '…' : ''}`;
  const keyboard = {
    inline_keyboard: [[
      { text: '↩️ Reply', callback_data: `reply:${kvKey}:${sender}:${subject}`.slice(0, 64) },
      { text: '🗑 Delete', callback_data: `delete:${kvKey}`.slice(0, 64) },
    ]]
  };
  for (const key of chats.keys) {
    const data = await env.AUTH_KV.get(key.name, 'json');
    if (data?.chatId) {
      await tgSend(token, data.chatId, msgText, { parse_mode: 'Markdown', reply_markup: JSON.stringify(keyboard) }).catch(() => {});
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

function recoverEthAddress(address, nonce, issuedAt, signature, env) {
  try {
    const reqUrl  = new URL('https://placeholder');
    const domain  = 'worker.yetazero.xyz';
    const chainId = getChainId(env.CHAIN_NAME || 'Ethereum');
    const message = buildSiweMessage({ domain, address, statement: 'Sign in to ETAMail. This request will not trigger a blockchain transaction or cost any gas.', uri: `https://${domain}`, version: '1', chainId, nonce, issuedAt });
    const msgBytes  = new TextEncoder().encode(message);
    const prefix    = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
    const prefixed  = concatBytes(prefix, msgBytes);
    const msgHash   = keccak_256(prefixed);
    const sigHex    = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBytes  = hexToBytes(sigHex);
    if (sigBytes.length !== 65) throw new Error(`Bad signature length: ${sigBytes.length}`);
    const r  = bytesToHex(sigBytes.slice(0, 32));
    const s  = bytesToHex(sigBytes.slice(32, 64));
    let v    = sigBytes[64];
    if (v >= 27) v -= 27;
    const sig       = secp256k1.Signature.fromCompact(`${r}${s}`).addRecoveryBit(v);
    const pubKeyObj = sig.recoverPublicKey(msgHash);
    const pubKeyData = pubKeyObj.toRawBytes(false).slice(1);
    const addrHash   = keccak_256(pubKeyData);
    return ('0x' + bytesToHex(addrHash.slice(-20))).toLowerCase();
  } catch (err) {
    console.error('[recoverEthAddress]', err);
    return '0x_recovery_failed';
  }
}

function buildSiweMessage({ domain, address, statement, uri, version, chainId, nonce, issuedAt }) {
  return [`${domain} wants you to sign in with your Ethereum account:`, address, '', statement, '', `URI: ${uri}`, `Version: ${version}`, `Chain ID: ${chainId}`, `Nonce: ${nonce}`, `Issued At: ${issuedAt}`].join('\n');
}

function getChainId(chainName) {
  const chains = { 'Ethereum': 1, 'BNB Smart Chain': 56, 'Polygon': 137, 'Avalanche': 43114, 'Arbitrum': 42161, 'Optimism': 10 };
  return chains[chainName] || 1;
}

async function generateSessionToken(address, secret, ttl) {
  const payload   = { sub: address, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+ttl, jti: bytesToHex(crypto.getRandomValues(new Uint8Array(16))) };
  const payloadB64 = btoa(JSON.stringify(payload));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', keyMaterial, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${arrayBufferToBase64url(sigBuf)}`;
}

function isValidEthAddress(addr) { return /^0x[0-9a-f]{40}$/i.test(addr); }
function extractToken(request)   { const a = request.headers.get('Authorization')||''; return a.startsWith('Bearer ') ? a.slice(7).trim() : null; }
function hexToBytes(hex)         { const r = new Uint8Array(hex.length/2); for (let i=0;i<hex.length;i+=2) r[i/2]=parseInt(hex.slice(i,i+2),16); return r; }
function bytesToHex(bytes)       { return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join(''); }
function concatBytes(a, b)       { const r = new Uint8Array(a.length+b.length); r.set(a,0); r.set(b,a.length); return r; }
function arrayBufferToBase64url(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }

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
  let decoded = enc === 'base64' ? body.replace(/\s/g,'') : enc === 'quoted-printable' ? decodeQP(body) : body;
  const csm     = ct.match(/charset\s*=\s*"?([^";]+)"?/i);
  const charset = csm ? csm[1].trim() : 'utf-8';
  if (ctLower.startsWith('text/html') && !isAttach)  { result.html += enc==='base64' ? b64Decode(decoded,charset) : decoded; return; }
  if (ctLower.startsWith('text/plain') && !isAttach) { result.text += enc==='base64' ? b64Decode(decoded,charset) : decoded; return; }
  const namem = ct.match(/name\s*=\s*"?([^";]+)"?/i) || disp.match(/filename\s*=\s*"?([^";]+)"?/i);
  const name  = namem ? namem[1].trim() : (cid || 'attachment');
  const b64   = enc === 'base64' ? decoded : btoa(decoded);
  result.attachments.push({ name, type: ctLower.split(';')[0].trim(), data: b64, contentId: cid || null, size: Math.round(b64.length*0.75) });
}

function parseHeaders(block) {
  const headers = {};
  for (const line of block.replace(/\r\n([ \t])/g,' ').split('\r\n')) {
    const idx = line.indexOf(':'); if (idx === -1) continue;
    headers[line.slice(0,idx).trim().toLowerCase()] = decodeRfc2047(line.slice(idx+1).trim());
  }
  return headers;
}

function splitMultipart(body, boundary) {
  const parts=[]; const delim=`--${boundary}`; const end=`--${boundary}--`;
  let current=[]; let inPart=false;
  for (const line of body.split('\r\n')) {
    if (line===end)   { if (inPart) parts.push(current.join('\r\n')); break; }
    if (line===delim) { if (inPart) parts.push(current.join('\r\n')); current=[]; inPart=true; continue; }
    if (inPart) current.push(line);
  }
  return parts;
}

function decodeQP(str)            { return str.replace(/=\r\n/g,'').replace(/=([0-9A-Fa-f]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16))); }
function b64Decode(b64, charset)  { try { return new TextDecoder(charset,{fatal:false}).decode(Uint8Array.from(atob(b64),c=>c.charCodeAt(0))); } catch { return atob(b64); } }
function decodeRfc2047(str)       { return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g,(_,charset,enc,text)=>{ try { const bytes=enc.toUpperCase()==='B'?Uint8Array.from(atob(text),c=>c.charCodeAt(0)):Uint8Array.from(decodeQP(text.replace(/_/g,' ')),c=>c.charCodeAt(0)); return new TextDecoder(charset,{fatal:false}).decode(bytes); } catch { return text; } }); }
function inlineCidImages(html, attachments) { return html.replace(/cid:([^"'\s>]+)/gi,(match,cid)=>{ const att=attachments.find(a=>a.contentId===cid); return att?`data:${att.type};base64,${att.data}`:match; }); }

function jsonResponse(data, status=200, request, env) {
  return new Response(JSON.stringify(data,null,2), { status, headers: { 'Content-Type':'application/json;charset=utf-8', 'Cache-Control':'no-store', ...getCorsHeaders(request,env) } });
}

function corsPreflightResponse(request, env) {
  return new Response(null, { status: 204, headers: { ...getCorsHeaders(request,env), 'Access-Control-Max-Age':'86400' } });
}

function getCorsHeaders(request, env) {
  const origin = request?.headers?.get('Origin') || '*';
  return { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Credentials': 'true', 'Vary': 'Origin' };
}
