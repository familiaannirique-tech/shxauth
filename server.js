/**
 * KEY AUTH — API de Licenças
 * Node.js + Express
 *
 * Endpoints:
 *   POST /api/activate   → ativa uma key (vincula HWID)
 *   POST /api/verify     → verifica se a key + HWID são válidos
 *   POST /api/reset-hwid → reseta o HWID de uma key (admin)
 *   GET  /api/keys       → lista todas as keys (admin)
 *   POST /api/generate   → gera novas keys (admin)
 *   DELETE /api/keys/:id → revoga uma key (admin)
 *
 * Headers obrigatórios (rotas admin):
 *   X-Admin-Secret: <ADMIN_SECRET>
 *
 * Instalar:  npm install
 * Iniciar:   node server.js
 */

const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const crypto     = require('crypto');
const fs         = require('fs');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ─── CONFIG ─── */
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin-secret-mude-isso';
const DB_FILE      = path.join(__dirname, 'db.json');

app.use(cors({
  origin: '*',
  methods: ['GET','POST','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Admin-Secret']
}));
app.options('*', cors());
app.use(bodyParser.json());

/* ═══════════════════════════════════
   DATABASE (JSON simples em disco)
═══════════════════════════════════ */
function loadDB() {
  const def = { keys: { Diario: [], Semanal: [], Mensal: [], Vitalicio: [] }, active: [] };
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(def, null, 2));
    return def;
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!db.keys || Array.isArray(db.keys)) db.keys = def.keys;
  if (!db.keys.Diario)    db.keys.Diario    = [];
  if (!db.keys.Semanal)   db.keys.Semanal   = [];
  if (!db.keys.Mensal)    db.keys.Mensal    = [];
  if (!db.keys.Vitalicio) db.keys.Vitalicio = [];
  if (!db.active) db.active = [];
  return db;
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

/* ═══════════════════════════════════
   UTILS
═══════════════════════════════════ */
function uid() {
  return crypto.randomBytes(8).toString('hex');
}

function generateKeyCode(prefix) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < 16; i++) s += chars[Math.floor(Math.random() * chars.length)];
  // format: PREFIX-XXXX-XXXX-XXXX-XXXX
  const p = (prefix || 'KEY').toUpperCase().slice(0, 6);
  return `${p}-${s.slice(0,4)}-${s.slice(4,8)}-${s.slice(8,12)}-${s.slice(12,16)}`;
}

function planDurationMs(plan) {
  switch (plan) {
    case 'Diario':    return 1 * 24 * 3600 * 1000;
    case 'Semanal':   return 7 * 24 * 3600 * 1000;
    case 'Mensal':    return 30 * 24 * 3600 * 1000;
    case 'Vitalicio': return null; // sem expiração
    default:          return null;
  }
}

function isAdmin(req) {
  return req.headers['x-admin-secret'] === ADMIN_SECRET;
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
}

/* ═══════════════════════════════════
   ROTA: POST /api/activate
   Ativa uma key e vincula o HWID
═══════════════════════════════════ */
app.post('/api/activate', (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) {
    return res.status(400).json({ success: false, message: 'key e hwid são obrigatórios' });
  }

  const db     = loadDB();
  const keyUp  = key.toUpperCase().trim();
  const hwidTr = hwid.trim();

  // Checar se já está ativa (key já vinculada)
  const alreadyActive = db.active.find(a => a.code === keyUp);
  if (alreadyActive) {
    // Mesmo HWID → retorna sucesso (re-login)
    if (alreadyActive.hwid === hwidTr) {
      const expired = alreadyActive.plan !== 'Vitalicio' && alreadyActive.expiresAt < Date.now();
      if (expired) {
        return res.json({ success: false, message: 'key_expired', plan: alreadyActive.plan });
      }
      return res.json({
        success:   true,
        message:   'already_active',
        plan:      alreadyActive.plan,
        expiresAt: alreadyActive.expiresAt || null
      });
    }
    // HWID diferente e não foi resetado
    if (alreadyActive.hwid !== null) {
      return res.json({ success: false, message: 'hwid_mismatch' });
    }
    // HWID foi resetado (null) → vincular novo HWID
    alreadyActive.hwid      = hwidTr;
    alreadyActive.resetAt   = null;
    alreadyActive.ip        = getClientIP(req);
    saveDB(db);
    return res.json({
      success:   true,
      message:   'hwid_rebound',
      plan:      alreadyActive.plan,
      expiresAt: alreadyActive.expiresAt || null
    });
  }

  // Procurar key pendente
  let foundPlan = null;
  let foundKey  = null;
  for (const plan of ['Diario','Semanal','Mensal','Vitalicio']) {
    const idx = (db.keys[plan] || []).findIndex(k => k.code === keyUp);
    if (idx !== -1) {
      foundPlan = plan;
      foundKey  = db.keys[plan][idx];
      db.keys[plan].splice(idx, 1);
      break;
    }
  }

  if (!foundKey) {
    return res.json({ success: false, message: 'invalid_key' });
  }

  const durMs     = planDurationMs(foundPlan);
  const expiresAt = durMs ? Date.now() + durMs : null;

  const record = {
    id:          uid(),
    code:        keyUp,
    plan:        foundPlan,
    hwid:        hwidTr,
    ip:          getClientIP(req),
    mbid:        req.body.mbid || null,
    activatedAt: new Date().toISOString(),
    expiresAt,
    resetAt:     null
  };

  db.active.push(record);
  saveDB(db);

  return res.json({
    success:   true,
    message:   'activated',
    plan:      foundPlan,
    expiresAt: expiresAt || null
  });
});

/* ═══════════════════════════════════
   ROTA: POST /api/verify
   Verifica key + HWID a cada boot
═══════════════════════════════════ */
app.post('/api/verify', (req, res) => {
  const { key, hwid } = req.body;

  if (!key || !hwid) {
    return res.status(400).json({ success: false, message: 'key e hwid são obrigatórios' });
  }

  const db    = loadDB();
  const keyUp = key.toUpperCase().trim();
  const rec   = db.active.find(a => a.code === keyUp);

  if (!rec) {
    return res.json({ success: false, message: 'invalid_key' });
  }

  if (rec.hwid !== hwid.trim()) {
    return res.json({ success: false, message: 'hwid_mismatch' });
  }

  if (rec.plan !== 'Vitalicio' && rec.expiresAt < Date.now()) {
    return res.json({ success: false, message: 'key_expired', plan: rec.plan });
  }

  return res.json({
    success:   true,
    message:   'valid',
    plan:      rec.plan,
    expiresAt: rec.expiresAt || null
  });
});

/* ═══════════════════════════════════
   ROTA: POST /api/reset-hwid  [ADMIN]
═══════════════════════════════════ */
app.post('/api/reset-hwid', requireAdmin, (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key é obrigatória' });

  const db  = loadDB();
  const rec = db.active.find(a => a.code === key.toUpperCase().trim());
  if (!rec) return res.json({ success: false, message: 'key não encontrada' });

  rec.hwid    = null;
  rec.resetAt = new Date().toISOString();
  saveDB(db);
  return res.json({ success: true, message: 'hwid_reset' });
});

/* ═══════════════════════════════════
   ROTA: POST /api/generate  [ADMIN]
═══════════════════════════════════ */
app.post('/api/generate', requireAdmin, (req, res) => {
  const { plan, qty, prefix } = req.body;
  const plans = ['Diario','Semanal','Mensal','Vitalicio'];
  if (!plans.includes(plan)) return res.status(400).json({ success: false, message: 'plano inválido' });

  const amount = Math.min(100, Math.max(1, parseInt(qty) || 1));
  const db     = loadDB();
  if (!db.keys) db.keys = { Diario: [], Semanal: [], Mensal: [], Vitalicio: [] };

  const generated = [];
  for (let i = 0; i < amount; i++) {
    const code = generateKeyCode(prefix || 'KEY');
    const entry = { id: uid(), code };
    db.keys[plan].push(entry);
    generated.push(code);
  }
  saveDB(db);
  return res.json({ success: true, generated, count: generated.length });
});

/* ═══════════════════════════════════
   ROTA: GET /api/keys  [ADMIN]
═══════════════════════════════════ */
app.get('/api/keys', requireAdmin, (req, res) => {
  const db = loadDB();
  return res.json({ success: true, keys: db.keys || {}, active: db.active || [] });
});

/* ═══════════════════════════════════
   ROTA: DELETE /api/keys/:id  [ADMIN]
═══════════════════════════════════ */
app.delete('/api/keys/:id', requireAdmin, (req, res) => {
  const db  = loadDB();
  const idx = (db.active || []).findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.json({ success: false, message: 'key não encontrada' });
  db.active.splice(idx, 1);
  saveDB(db);
  return res.json({ success: true, message: 'key_deleted' });
});

/* ═══════════════════════════════════
   ROTA: POST /api/add-time  [ADMIN]
═══════════════════════════════════ */
app.post('/api/add-time', requireAdmin, (req, res) => {
  const { id, amt, unit } = req.body;
  if (!id || !amt) return res.status(400).json({ success: false, message: 'id e amt obrigatórios' });
  const db  = loadDB();
  const rec = (db.active || []).find(a => a.id === id);
  if (!rec) return res.json({ success: false, message: 'key não encontrada' });
  if (rec.plan === 'Vitalicio') return res.json({ success: false, message: 'key vitalícia' });
  const ms = unit === 'hour' ? amt * 3600000 : amt * 86400000;
  rec.expiresAt = Math.max(Date.now(), rec.expiresAt || Date.now()) + ms;
  saveDB(db);
  return res.json({ success: true, message: 'time_added', expiresAt: rec.expiresAt });
});

/* ═══════════════════════════════════
   ROTA: GET /api/health
═══════════════════════════════════ */
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'ok', ts: Date.now() });
});

app.listen(PORT, () => {
  console.log(`\n╔══════════════════════════════════╗`);
  console.log(`║  KEY AUTH API rodando na :${PORT}   ║`);
  console.log(`╚══════════════════════════════════╝\n`);
  console.log(`  Admin Secret : ${ADMIN_SECRET}`);
  console.log(`  DB File      : ${DB_FILE}\n`);
  console.log(`  Endpoints:`);
  console.log(`    POST   /api/activate`);
  console.log(`    POST   /api/verify`);
  console.log(`    POST   /api/reset-hwid  [admin]`);
  console.log(`    POST   /api/generate    [admin]`);
  console.log(`    GET    /api/keys        [admin]`);
  console.log(`    DELETE /api/keys/:id    [admin]\n`);
});
