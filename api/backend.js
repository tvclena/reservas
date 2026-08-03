const crypto = require('crypto');

const COOKIE_NAME = 'mercatto_project_session';
const MAX_AGE = 60 * 60 * 12;

function env(name, required = true) {
  const value = process.env[name];
  if (required && !value) throw new Error(`Variável ${name} não configurada na Vercel.`);
  return value || '';
}

function json(res, status, body, extraHeaders = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  for (const [key, value] of Object.entries(extraHeaders)) res.setHeader(key, value);
  res.end(JSON.stringify(body));
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function authorizedEmails() {
  return env('AUTHORIZED_EMAILS').split(',').map(normalizeEmail).filter(Boolean);
}

function isAuthorized(email) {
  return authorizedEmails().includes(normalizeEmail(email));
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signSession(payload) {
  const encoded = base64url(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', env('APP_SESSION_SECRET')).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}

function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [encoded, signature] = token.split('.');
  const expected = crypto.createHmac('sha256', env('APP_SESSION_SECRET')).update(encoded).digest('base64url');
  const a = Buffer.from(signature || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  if (!payload.exp || Date.now() > payload.exp) return null;
  if (!isAuthorized(payload.email)) return null;
  return payload;
}

function cookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function sessionFromRequest(req) {
  return verifySession(cookies(req)[COOKIE_NAME]);
}

function sessionCookie(token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${MAX_AGE}${secure}`;
}

function clearCookie() {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`;
}

async function supabaseAuth(path, options = {}) {
  const url = `${env('SUPABASE_URL').replace(/\/$/, '')}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      apikey: env('SUPABASE_ANON_KEY'),
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.msg || data.error_description || data.message || 'Falha de autenticação.');
  return data;
}

async function dbRequest(path, options = {}) {
  const response = await fetch(`${env('SUPABASE_URL').replace(/\/$/, '')}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: env('SUPABASE_SERVICE_ROLE_KEY'),
      Authorization: `Bearer ${env('SUPABASE_SERVICE_ROLE_KEY')}`,
      'Content-Type': 'application/json',
      Prefer: options.prefer || 'return=representation',
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.message || data?.hint || `Erro no banco (${response.status}).`);
  return data;
}

function reservasTable() {
  const table = env('RESERVAS_TABLE');
  if (!/^[a-zA-Z0-9_]+$/.test(table)) throw new Error('RESERVAS_TABLE inválida.');
  return table;
}

function safeId(id) {
  const value = String(id || '').trim();
  if (!/^[a-zA-Z0-9-]+$/.test(value)) throw new Error('ID inválido.');
  return encodeURIComponent(value);
}

async function handleAction(action, body, req, res) {
  if (action === 'auth.login') {
    const email = normalizeEmail(body.email);
    if (!email || !body.password) return json(res, 400, { message: 'Informe e-mail e senha.' });
    if (!isAuthorized(email)) return json(res, 403, { message: 'Este e-mail não está autorizado neste projeto.' });

    const auth = await supabaseAuth('/auth/v1/token?grant_type=password', {
      method: 'POST',
      body: JSON.stringify({ email, password: body.password })
    });
    const authenticatedEmail = normalizeEmail(auth.user?.email);
    if (!authenticatedEmail || authenticatedEmail !== email || !isAuthorized(authenticatedEmail)) {
      return json(res, 403, { message: 'Acesso não autorizado para este projeto.' });
    }

    const payload = {
      sub: auth.user.id,
      email: authenticatedEmail,
      name: auth.user.user_metadata?.nome || auth.user.user_metadata?.name || authenticatedEmail.split('@')[0],
      companyName: env('COMPANY_NAME', false) || 'Empresa autorizada',
      exp: Date.now() + MAX_AGE * 1000
    };
    const token = signSession(payload);
    return json(res, 200, { user: payload }, { 'Set-Cookie': sessionCookie(token), 'Cache-Control': 'no-store' });
  }

  if (action === 'auth.logout') {
    return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie(), 'Cache-Control': 'no-store' });
  }

  if (action === 'auth.recover') {
    const email = normalizeEmail(body.email);
    if (email && isAuthorized(email)) {
      await supabaseAuth('/auth/v1/recover', {
        method: 'POST',
        body: JSON.stringify({ email, gotrue_meta_security: {}, redirect_to: body.redirectTo || undefined })
      });
    }
    return json(res, 200, { ok: true });
  }

  const session = sessionFromRequest(req);
  if (!session) return json(res, 401, { message: 'Sessão inválida ou expirada.' }, { 'Set-Cookie': clearCookie() });

  if (action === 'auth.session') {
    return json(res, 200, { user: session }, { 'Cache-Control': 'no-store' });
  }

  const table = reservasTable();

  if (action === 'reservas.listar') {
    const start = encodeURIComponent(String(body.start || ''));
    const end = encodeURIComponent(String(body.end || ''));
    const data = await dbRequest(`${table}?select=*&datahora=gte.${start}&datahora=lt.${end}&order=datahora.asc`, { method: 'GET' });
    return json(res, 200, { data });
  }

  if (action === 'reservas.cadastrar') {
    const data = await dbRequest(table, { method: 'POST', body: JSON.stringify(body.payload || {}) });
    return json(res, 200, { data });
  }

  if (action === 'reservas.atualizar') {
    const data = await dbRequest(`${table}?id=eq.${safeId(body.id)}`, { method: 'PATCH', body: JSON.stringify(body.payload || {}) });
    return json(res, 200, { data });
  }

  if (action === 'reservas.excluir') {
    await dbRequest(`${table}?id=eq.${safeId(body.id)}`, { method: 'DELETE' });
    return json(res, 200, { ok: true });
  }

  if (action === 'downloads.registrar') {
    const payload = { ...(body.payload || {}), empresa: env('COMPANY_NAME', false) || 'Empresa' };
    const data = await dbRequest('downloads_do_sistema', { method: 'POST', body: JSON.stringify(payload) });
    return json(res, 200, { data });
  }

  if (action === 'impressao.buscarUrl') {
    const types = [body.tipoPrincipal, body.tipoFallback].filter(Boolean);
    for (const type of types) {
      const encoded = encodeURIComponent(String(type));
      const data = await dbRequest(`url_api?select=*&ativo=eq.true&tipo=eq.${encoded}&order=created_at.desc&limit=1`, { method: 'GET' });
      if (Array.isArray(data) && data[0]) return json(res, 200, { data: data[0] });
    }
    return json(res, 200, { data: null });
  }

  if (action === 'impressao.atualizarStatus') {
    const data = await dbRequest(`url_api?id=eq.${safeId(body.id)}`, { method: 'PATCH', body: JSON.stringify(body.payload || {}) });
    return json(res, 200, { data });
  }

  if (action === 'relatorios.upload') {
    const fileName = String(body.nomeArquivo || '').replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!fileName || !body.arquivoBase64) return json(res, 400, { message: 'Arquivo inválido.' });
    const bucket = env('REPORTS_BUCKET', false) || 'relatorios';
    const bytes = Buffer.from(body.arquivoBase64, 'base64');
    if (bytes.length > 4.5 * 1024 * 1024) return json(res, 413, { message: 'PDF muito grande para esta função.' });
    const upload = await fetch(`${env('SUPABASE_URL').replace(/\/$/, '')}/storage/v1/object/${encodeURIComponent(bucket)}/${encodeURIComponent(fileName)}`, {
      method: 'POST',
      headers: {
        apikey: env('SUPABASE_SERVICE_ROLE_KEY'),
        Authorization: `Bearer ${env('SUPABASE_SERVICE_ROLE_KEY')}`,
        'Content-Type': body.contentType || 'application/pdf',
        'x-upsert': 'true'
      },
      body: bytes
    });
    if (!upload.ok) {
      const error = await upload.text();
      throw new Error(error || 'Falha no upload do relatório.');
    }
    const publicUrl = `${env('SUPABASE_URL').replace(/\/$/, '')}/storage/v1/object/public/${encodeURIComponent(bucket)}/${encodeURIComponent(fileName)}`;
    return json(res, 200, { publicUrl });
  }

  return json(res, 400, { message: 'Ação inválida.' });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { message: 'Método não permitido.' });
  res.setHeader('Cache-Control', 'no-store');
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    await handleAction(body.action, body, req, res);
  } catch (error) {
    console.error(error);
    const message = String(error?.message || 'Erro interno.');
    const authError = /login|credentials|senha|password/i.test(message);
    json(res, authError ? 401 : 500, { message: authError ? 'E-mail ou senha inválidos.' : message });
  }
};
