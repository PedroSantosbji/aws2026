// api/lead.js — Vercel Serverless Function
//
// Proxy seguro entre o formulário público e o Google Apps Script.
//
// Camadas de segurança aplicadas aqui:
//   1. Aceita só POST.
//   2. Origin/Referer check contra ALLOWED_ORIGINS (CSRF).
//   3. Honeypot: campo invisível "website" — se preenchido, é bot.
//   4. Rate limit por IP (em memória, sliding window).
//   5. Validação server-side (re-checa tudo que o front valida).
//   6. Sanitização + truncamento de cada campo.
//   7. Forwarding com APPS_SCRIPT_SECRET (Apps Script rejeita se não bater).
//   8. Headers de segurança no response.
//
// Variáveis de ambiente esperadas (configurar no Vercel → Settings → Environment Variables):
//   APPS_SCRIPT_URL       — URL /exec do Apps Script
//   APPS_SCRIPT_SECRET    — string aleatória, idêntica à do Apps Script
//   ALLOWED_ORIGINS       — opcional, lista separada por vírgula. Ex:
//                           "https://www.guidance.dev,https://guidance.dev"

const APPS_SCRIPT_URL = process.env.APPS_SCRIPT_URL || '';
const APPS_SCRIPT_SECRET = process.env.APPS_SCRIPT_SECRET || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// Rate limit (por IP, janela deslizante de 60s). Roda na instância serverless;
// reinicia a cada cold start, o que é suficiente para conter spam casual.
// Para algo mais agressivo, plugar Upstash/Redis aqui.
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 60_000;
const hits = new Map();

const isEmail = v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v || '');
const isPhone = v => (v || '').replace(/\D/g, '').length >= 10;
const str = (v, max = 500) => (v == null ? '' : String(v)).trim().slice(0, max);

function originOk(req) {
  if (ALLOWED_ORIGINS.length === 0) return true; // não configurado → libera
  const candidates = [
    req.headers.origin,
    req.headers.referer,
  ].filter(Boolean);
  if (candidates.length === 0) return false;
  return candidates.some(c => ALLOWED_ORIGINS.some(o => c === o || c.startsWith(o + '/') || c.startsWith(o + '?')));
}

function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket && req.socket.remoteAddress || 'unknown';
}

function rateLimit(ip) {
  const now = Date.now();
  const log = (hits.get(ip) || []).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  if (log.length >= RATE_LIMIT_MAX) return false;
  log.push(now);
  hits.set(ip, log);
  return true;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    // Vercel já parseia req.body por padrão; usar isso quando presente.
    if (req.body && typeof req.body === 'object') return resolve(req.body);
    if (typeof req.body === 'string') {
      try { return resolve(JSON.parse(req.body)); } catch { return resolve({}); }
    }
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 64 * 1024) { req.destroy(); reject(new Error('payload too large')); }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  // Security headers no response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  if (!originOk(req)) {
    return res.status(403).json({ ok: false, error: 'Origin not allowed' });
  }

  const ip = getIp(req);
  if (!rateLimit(ip)) {
    return res.status(429).json({ ok: false, error: 'Muitas tentativas. Aguarde um momento.' });
  }

  let body;
  try { body = await readBody(req); }
  catch { return res.status(400).json({ ok: false, error: 'Invalid body' }); }

  // Honeypot — se preenchido, finge sucesso e descarta
  if (body.website && String(body.website).trim().length > 0) {
    return res.status(200).json({ ok: true });
  }

  // Sanitização + extração
  const nome     = str(body.nome, 200);
  const email    = str(body.email, 200).toLowerCase();
  const telefone = str(body.telefone, 50);
  const cargo    = str(body.cargo, 200);
  const empresa  = str(body.empresa, 200);
  const desafio  = str(body.desafio, 5000);
  const consent  = body.consent === true || body.consent === 'true';
  const origem   = str(body.origem, 200) || 'LP AWS Guidance';
  const pagina   = str(body.pagina, 500);

  // Validação server-side (mesmo critério do client)
  const errors = [];
  if (nome.length < 2) errors.push('nome');
  if (!isEmail(email)) errors.push('email');
  if (!isPhone(telefone)) errors.push('telefone');
  if (cargo.length < 2) errors.push('cargo');
  if (empresa.length < 2) errors.push('empresa');
  if (!consent) errors.push('consent');
  if (errors.length) {
    return res.status(400).json({ ok: false, error: 'Validation failed', fields: errors });
  }

  if (!APPS_SCRIPT_URL) {
    console.error('[lead] APPS_SCRIPT_URL não configurado');
    return res.status(500).json({ ok: false, error: 'Server misconfigured' });
  }

  // Encaminhar para o Apps Script
  const params = new URLSearchParams();
  params.append('secret', APPS_SCRIPT_SECRET); // valida no servidor
  params.append('timestamp', new Date().toISOString());
  params.append('nome', nome);
  params.append('email', email);
  params.append('telefone', telefone);
  params.append('cargo', cargo);
  params.append('empresa', empresa);
  params.append('desafio', desafio);
  params.append('consent', consent ? 'true' : 'false');
  params.append('origem', origem);
  params.append('pagina', pagina);
  params.append('ip', ip);
  params.append('ua', str(req.headers['user-agent'], 500));

  try {
    const upstream = await fetch(APPS_SCRIPT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      redirect: 'follow',
    });
    if (!upstream.ok) {
      console.error('[lead] Apps Script HTTP', upstream.status);
      return res.status(502).json({ ok: false, error: 'Upstream error' });
    }
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('[lead] forward failed:', err);
    return res.status(502).json({ ok: false, error: 'Upstream error' });
  }
};
