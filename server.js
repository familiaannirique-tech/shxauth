/***
 * KEY AUTH — API de Licenças
 * Node.js + Express + MongoDB Atlas
 *
 * Endpoints:
 *   POST   /api/activate              → ativa uma key (vincula HWID)
 *   POST   /api/verify                → verifica se a key + HWID são válidos
 *   POST   /api/reset-hwid            → reseta o HWID de uma key (admin)
 *   GET    /api/keys                  → lista todas as keys (admin)
 *   POST   /api/generate              → gera novas keys (admin)
 *   DELETE /api/keys/:id              → revoga uma key ativa (admin)
 *   POST   /api/add-time              → adiciona tempo a uma key (admin)
 *   DELETE /api/keys/pending/:plan    → limpa keys pendentes de um plano (admin)
 *   DELETE /api/keys/pending/:plan/:id→ remove key pendente específica (admin)
 *   GET    /api/health                → health check
 *
 * Variáveis de ambiente no Render:
 *   MONGODB_URI   → connection string do MongoDB Atlas
 *   ADMIN_SECRET  → senha admin do painel
 *   PORT          → (opcional) porta, padrão 3000
 */

const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const crypto     = require('crypto');
const { MongoClient } = require('mongodb');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ─── CONFIG ─── */
const ADMIN_SECRET  = process.env.ADMIN_SECRET  || 'ADMIN_SECRET';
const MONGODB_URI   = process.env.MONGODB_URI   || '';

if (!MONGODB_URI) {
  console.error('ERRO: variável MONGODB_URI não definida!');
  process.exit(1);
}

app.use(cors({
  origin: '*',
  methods: ['GET','POST','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','X-Admin-Secret']
}));
app.options('*', cors());
app.use(bodyParser.json());

/* ═══════════════════════════════════
   MONGODB
═══════════════════════════════════ */
let db;

async function connectDB() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db('keyauth');
  console.log('✅ MongoDB conectado');
}

function keys()   { return db.collection('keys');   }  // keys pendentes: { plan, id, code }
function active() { return db.collection('active'); }  // keys ativas

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
  const p = (prefix || 'KEY').toUpperCase().slice(0, 6);
  return `${p}-${s.slice(0,4)}-${s.slice(4,8)}-${s.slice(8,12)}-${s.slice(12,16)}`;
}

function planDurationMs(plan) {
  switch (plan) {
    case 'Diario':    return 1  * 24 * 3600 * 1000;
    case 'Semanal':   return 7  * 24 * 3600 * 1000;
    case 'Mensal':    return 30 * 24 * 3600 * 1000;
    case 'Vitalicio': return null;
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
═══════════════════════════════════ */
app.post('/api/activate', async (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid)
    return res.status(400).json({ success: false, message: 'key e hwid são obrigatórios' });

  const keyUp  = key.toUpperCase().trim();
  const hwidTr = hwid.trim();

  // Já está ativa?
  const alreadyActive = await active().findOne({ code: keyUp });
  if (alreadyActive) {
    if (alreadyActive.hwid === hwidTr) {
      const expired = alreadyActive.plan !== 'Vitalicio' && alreadyActive.expiresAt < Date.now();
      if (expired)
        return res.json({ success: false, message: 'key_expired', plan: alreadyActive.plan });
      return res.json({ success: true, message: 'already_active', plan: alreadyActive.plan, expiresAt: alreadyActive.expiresAt || null });
    }
    if (alreadyActive.hwid !== null)
      return res.json({ success: false, message: 'hwid_mismatch' });

    // HWID foi resetado → vincular novo
    await active().updateOne({ code: keyUp }, { $set: { hwid: hwidTr, resetAt: null, ip: getClientIP(req) } });
    return res.json({ success: true, message: 'hwid_rebound', plan: alreadyActive.plan, expiresAt: alreadyActive.expiresAt || null });
  }

  // Procurar key pendente
  const plans = ['Diario','Semanal','Mensal','Vitalicio'];
  let foundKey = null;
  let foundPlan = null;

  for (const plan of plans) {
    foundKey = await keys().findOne({ plan, code: keyUp });
    if (foundKey) {
      foundPlan = plan;
      await keys().deleteOne({ _id: foundKey._id });
      break;
    }
  }

  if (!foundKey)
    return res.json({ success: false, message: 'invalid_key' });

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

  await active().insertOne(record);

  return res.json({ success: true, message: 'activated', plan: foundPlan, expiresAt: expiresAt || null });
});

/* ═══════════════════════════════════
   ROTA: POST /api/verify
═══════════════════════════════════ */
app.post('/api/verify', async (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid)
    return res.status(400).json({ success: false, message: 'key e hwid são obrigatórios' });

  const keyUp = key.toUpperCase().trim();
  const rec   = await active().findOne({ code: keyUp });

  if (!rec)
    return res.json({ success: false, message: 'invalid_key' });
  if (rec.hwid !== hwid.trim())
    return res.json({ success: false, message: 'hwid_mismatch' });
  if (rec.plan !== 'Vitalicio' && rec.expiresAt < Date.now())
    return res.json({ success: false, message: 'key_expired', plan: rec.plan });

  return res.json({ success: true, message: 'valid', plan: rec.plan, expiresAt: rec.expiresAt || null });
});

/* ═══════════════════════════════════
   ROTA: POST /api/reset-hwid [ADMIN]
═══════════════════════════════════ */
app.post('/api/reset-hwid', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'key é obrigatória' });

  const rec = await active().findOne({ code: key.toUpperCase().trim() });
  if (!rec) return res.json({ success: false, message: 'key não encontrada' });

  await active().updateOne({ _id: rec._id }, { $set: { hwid: null, resetAt: new Date().toISOString() } });
  return res.json({ success: true, message: 'hwid_reset' });
});

/* ═══════════════════════════════════
   ROTA: POST /api/generate [ADMIN]
═══════════════════════════════════ */
app.post('/api/generate', requireAdmin, async (req, res) => {
  const { plan, qty, prefix } = req.body;
  const plans = ['Diario','Semanal','Mensal','Vitalicio'];
  if (!plans.includes(plan))
    return res.status(400).json({ success: false, message: 'plano inválido' });

  const amount = Math.min(100, Math.max(1, parseInt(qty) || 1));
  const generated = [];
  const docs = [];

  for (let i = 0; i < amount; i++) {
    const code = generateKeyCode(prefix || 'KEY');
    docs.push({ id: uid(), plan, code });
    generated.push(code);
  }

  await keys().insertMany(docs);
  return res.json({ success: true, generated, count: generated.length });
});

/* ═══════════════════════════════════
   ROTA: GET /api/keys [ADMIN]
═══════════════════════════════════ */
app.get('/api/keys', requireAdmin, async (req, res) => {
  const allKeys   = await keys().find({}).toArray();
  const allActive = await active().find({}).toArray();

  const grouped = { Diario: [], Semanal: [], Mensal: [], Vitalicio: [] };
  allKeys.forEach(k => {
    if (grouped[k.plan]) grouped[k.plan].push({ id: k.id, code: k.code });
  });

  // Remove _id do MongoDB antes de enviar pro frontend
  const cleanActive = allActive.map(({ _id, ...rest }) => rest);

  return res.json({ success: true, keys: grouped, active: cleanActive });
});

/* ═══════════════════════════════════
   ROTA: DELETE /api/keys/pending/:plan [ADMIN]
   (deve vir ANTES de /api/keys/:id)
═══════════════════════════════════ */
app.delete('/api/keys/pending/:plan', requireAdmin, async (req, res) => {
  const valid = ['Diario','Semanal','Mensal','Vitalicio'];
  if (!valid.includes(req.params.plan))
    return res.status(400).json({ success: false, message: 'plano inválido' });

  const result = await keys().deleteMany({ plan: req.params.plan });
  return res.json({ success: true, removed: result.deletedCount });
});

/* ═══════════════════════════════════
   ROTA: DELETE /api/keys/pending/:plan/:id [ADMIN]
═══════════════════════════════════ */
app.delete('/api/keys/pending/:plan/:id', requireAdmin, async (req, res) => {
  const valid = ['Diario','Semanal','Mensal','Vitalicio'];
  if (!valid.includes(req.params.plan))
    return res.status(400).json({ success: false, message: 'plano inválido' });

  const result = await keys().deleteOne({ plan: req.params.plan, id: req.params.id });
  return res.json({ success: true, removed: result.deletedCount });
});

/* ═══════════════════════════════════
   ROTA: DELETE /api/keys/:id [ADMIN]
═══════════════════════════════════ */
app.delete('/api/keys/:id', requireAdmin, async (req, res) => {
  const result = await active().deleteOne({ id: req.params.id });
  if (result.deletedCount === 0)
    return res.json({ success: false, message: 'key não encontrada' });
  return res.json({ success: true, message: 'key_deleted' });
});

/* ═══════════════════════════════════
   ROTA: POST /api/add-time [ADMIN]
═══════════════════════════════════ */
app.post('/api/add-time', requireAdmin, async (req, res) => {
  const { id, amt, unit } = req.body;
  if (!id || !amt)
    return res.status(400).json({ success: false, message: 'id e amt obrigatórios' });

  const rec = await active().findOne({ id });
  if (!rec) return res.json({ success: false, message: 'key não encontrada' });
  if (rec.plan === 'Vitalicio') return res.json({ success: false, message: 'key vitalícia' });

  const ms        = unit === 'hour' ? amt * 3600000 : amt * 86400000;
  const expiresAt = Math.max(Date.now(), rec.expiresAt || Date.now()) + ms;

  await active().updateOne({ id }, { $set: { expiresAt } });
  return res.json({ success: true, message: 'time_added', expiresAt });
});

/* ═══════════════════════════════════
   ROTA: GET /api/health
═══════════════════════════════════ */
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'ok', ts: Date.now() });
});

/* ═══════════════════════════════════
   START
═══════════════════════════════════ */
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n╔══════════════════════════════════╗`);
    console.log(`║  KEY AUTH API rodando na :${PORT}   ║`);
    console.log(`╚══════════════════════════════════╝\n`);
    console.log(`  Admin Secret : ${ADMIN_SECRET}`);
    console.log(`  MongoDB      : conectado\n`);
  });
}).catch(err => {
  console.error('Falha ao conectar no MongoDB:', err);
  process.exit(1);
});
