/**
 * 胖胖體育 Backend API
 * MySQL + Express.js
 * Database: my_database
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const mysql     = require('mysql2/promise');
const bcrypt    = require('bcrypt');
const crypto    = require('crypto');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');
const cron      = require('node-cron');
const https     = require('https');
const http      = require('http');
const fs        = require('fs');
const { encrypt, decrypt, ecpayCheckMac } = require('./utils/encrypt');

const app = express();

// ── 安全標頭（Helmet）────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'"],
      styleSrc:    ["'self'", "'unsafe-inline'"],
      imgSrc:      ["'self'", 'data:', 'https:'],
      connectSrc:  ["'self'", 'https:'],
      frameAncestors: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ── CORS 白名單 ──────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(o => o.trim()).filter(Boolean);

if (!ALLOWED_ORIGINS.length) {
  // 開發階段開放；正式環境請在 .env 設定 ALLOWED_ORIGINS
  app.use(cors());
} else {
  app.use(cors({
    origin: (origin, cb) => {
      // 允許 server-to-server（無 origin）或白名單內的來源
      if (!origin || ALLOWED_ORIGINS.some(o => origin === o || origin.endsWith(o))) {
        cb(null, true);
      } else {
        cb(new Error(`CORS blocked: ${origin}`));
      }
    },
    credentials: true,
  }));
}

app.use(express.json({ limit: '10mb' }));
app.use(morgan('[:date[iso]] :method :url :status :response-time ms - :remote-addr'));

// ── 可疑請求偵測（SQL Injection / Path Traversal / Scanner）─────
const ATTACK_PATTERNS = [
  /(\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|\bINSERT\b.*\bINTO\b)/i,
  /(<script[\s>]|javascript:|onerror=|onload=)/i,
  /(\.\.[/\\]){2,}/,
  /(\/etc\/passwd|\/proc\/self|cmd\.exe|powershell)/i,
];

app.use((req, res, next) => {
  const target = req.url + JSON.stringify(req.body || '');
  if (ATTACK_PATTERNS.some(p => p.test(target))) {
    console.warn(`🚨 可疑請求 [${req.ip}] ${req.method} ${req.url}`);
    return res.status(400).json({ error: '無效請求' });
  }
  next();
});

// ── Rate Limiting ─────────────────────────────────────────────────
const generalLimit = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn(`⚠️  Rate limit 超過 [${req.ip}] ${req.method} ${req.url}`);
    res.status(429).json({ error: '請求過於頻繁，請稍後再試' });
  },
});

const authLimit = rateLimit({
  windowMs: 15 * 60_000,  // 15 分鐘
  max: 5,
  message: { error: '登入嘗試次數過多，請 15 分鐘後再試' },
  handler: (req, res) => {
    console.warn(`🔒 Auth brute-force 嘗試 [${req.ip}]`);
    res.status(429).json({ error: '登入嘗試次數過多，請 15 分鐘後再試' });
  },
});

const adminLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  message: { error: '管理端點請求過於頻繁' },
});

app.use('/api/auth', authLimit);
app.use('/api/user/login', authLimit);
app.use('/api/admin', adminLimit);
app.use(generalLimit);

// ── 分析路由（業務邏輯後端化）───────────────────────────────────
const bingoAnalyzeRouter   = require('./routes/bingo_analyze');
const lotteryPredictRouter = require('./routes/lottery_predict');
const analysisRouter       = require('./routes/analysis');
app.use('/api/bingo',          bingoAnalyzeRouter);
app.use('/api/lottery/539',    lotteryPredictRouter);
app.use('/api/analysis',       analysisRouter);

// ── Admin Key + HMAC 簽章驗證 middleware ────────────────────────
// 請求端需附帶：
//   x-admin-key: <ADMIN_KEY>
//   x-timestamp: <Unix 毫秒>
//   x-signature: HMAC-SHA256(ADMIN_KEY, "timestamp=<ts>&method=<METHOD>&path=<PATH>")
function requireAdminKey(req, res, next) {
  const key  = req.headers['x-admin-key'];
  const ts   = req.headers['x-timestamp'];
  const sig  = req.headers['x-signature'];

  if (!key || key !== process.env.ADMIN_KEY) {
    console.warn(`🚫 Admin Key 驗證失敗 [${req.ip}] ${req.method} ${req.url}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  // 若有提供 HMAC 簽章，則額外驗證（防重放攻擊）
  if (ts && sig) {
    const age = Date.now() - parseInt(ts, 10);
    if (isNaN(age) || age > 5 * 60 * 1000 || age < -30_000) {
      return res.status(403).json({ error: 'Request timestamp expired' });
    }
    const payload  = `timestamp=${ts}&method=${req.method}&path=${req.path}`;
    const expected = crypto.createHmac('sha256', process.env.ADMIN_KEY).update(payload).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
      console.warn(`🚫 Admin HMAC 驗證失敗 [${req.ip}]`);
      return res.status(403).json({ error: 'Invalid signature' });
    }
  }

  next();
}

// ── MySQL 連線池 ────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.MYSQL_HOST     || 'localhost',
  port:     parseInt(process.env.MYSQL_PORT || '3306'),
  user:     process.env.MYSQL_USER     || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'my_database',
  waitForConnections: true,
  connectionLimit:    10,
  timezone: '+08:00',
  charset:  'utf8mb4',
});

pool.getConnection()
  .then(conn => { conn.release(); console.log('✅ MySQL 連線成功'); })
  .catch(err  => console.error('❌ MySQL 連線失敗:', err.message));
app.set('pool', pool);

// ── 工具函式 ────────────────────────────────────────────────────
const json = (v) => (v == null ? null : JSON.stringify(v));
const parse = (v) => {
  if (v == null) return null;
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch { return v; }
};

// ── Health check ────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ── Email 登入驗證（檢查 users 表訂閱是否有效）─────────────────
app.post('/api/auth/email', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.json({ valid: false, reason: 'no_email' });
  try {
    const [rows] = await pool.execute(
      `SELECT id, name, auth_expires_at, is_active FROM users WHERE email = ?`,
      [email]
    );
    if (!rows.length) return res.json({ valid: false, reason: 'not_found' });
    const u = rows[0];
    if (!u.is_active) return res.json({ valid: false, reason: 'inactive' });
    if (u.auth_expires_at && new Date(u.auth_expires_at) < new Date()) {
      return res.json({ valid: false, reason: 'expired', expiresAt: u.auth_expires_at });
    }
    res.json({
      valid: true,
      name: u.name || '',
      expiresAt: u.auth_expires_at,
    });
  } catch (e) {
    res.status(500).json({ valid: false, reason: e.message });
  }
});

// ── 網站密碼驗證（bcrypt 比對）──────────────────────────────────
app.post('/api/auth/password', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ valid: false });
  try {
    const [[row]] = await pool.execute(
      "SELECT value_enc FROM app_config WHERE key_name='admin_password_hash'"
    );
    if (!row) return res.json({ valid: false });
    const valid = await bcrypt.compare(password, row.value_enc);
    if (!valid) console.warn(`🔒 密碼驗證失敗 [${req.ip}]`);
    res.json({ valid });
  } catch (e) {
    res.status(500).json({ valid: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 用戶 / 認證
// ════════════════════════════════════════════════════════════════

app.post('/api/submit-email', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ success: false, message: '請輸入 Email' });
  try {
    await pool.execute(
      `INSERT INTO users (email, auth_expires_at)
       VALUES (?, DATE_ADD(NOW(), INTERVAL 3 DAY))
       ON DUPLICATE KEY UPDATE updated_at = NOW()`,
      [email]
    );
    res.json({ success: true, message: '已記錄 Email' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ valid: false });
  try {
    const [rows] = await pool.execute(
      'SELECT auth_expires_at, is_active FROM users WHERE email = ?', [email]
    );
    if (!rows.length) return res.json({ valid: false, reason: 'not_found' });
    const u = rows[0];
    if (!u.is_active) return res.json({ valid: false, reason: 'inactive' });
    if (u.auth_expires_at && new Date(u.auth_expires_at) < new Date()) {
      return res.json({ valid: false, reason: 'expired', expiresAt: u.auth_expires_at });
    }
    res.json({ valid: true, expiresAt: u.auth_expires_at });
  } catch (e) {
    res.status(500).json({ valid: false, reason: e.message });
  }
});

// 開通 / 更新訂閱（管理員用）
app.post('/api/admin/users', requireAdminKey, async (req, res) => {
  const { email, expiresAt } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    await pool.execute(
      `INSERT INTO users (email, auth_expires_at)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE auth_expires_at = ?, is_active = TRUE, updated_at = NOW()`,
      [email, expiresAt || null, expiresAt || null]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 用戶登入（email 驗證，無 2FA）
app.post('/api/user/login', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    const [[user]] = await pool.execute(
      `SELECT auth_expires_at, is_active FROM users WHERE email=?`, [email]
    );
    if (!user) return res.json({ valid: false, reason: 'not_found' });
    if (!user.is_active) return res.json({ valid: false, reason: 'inactive' });
    if (user.auth_expires_at && new Date(user.auth_expires_at) < new Date())
      return res.json({ valid: false, reason: 'expired' });
    res.json({ valid: true, expiresAt: user.auth_expires_at });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 預測記錄（體育 / 樂透 / 賓果 統一）
// ════════════════════════════════════════════════════════════════

app.get('/api/predictions', async (req, res) => {
  const { type } = req.query;
  const days   = Math.min(parseInt(req.query.days   || '7'),  90);
  const limit  = Math.min(parseInt(req.query.limit  || '50'), 200);  // 預設50，最多200
  const offset = Math.max(parseInt(req.query.offset || '0'),  0);
  try {
    const params = [];
    let sql = 'SELECT * FROM prediction_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)';
    params.push(days);
    if (type) { sql += ' AND type = ?'; params.push(type); }
    sql += ` ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`;
    const [rows] = await pool.execute(sql, params);
    // 回傳總數供前端分頁
    const [countRows] = await pool.execute(
      'SELECT COUNT(*) AS total FROM prediction_logs WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)' + (type ? ' AND type = ?' : ''),
      type ? [days, type] : [days]
    );
    res.json({ data: rows.map(r => ({ ...r, details: parse(r.details) })), total: countRows[0].total, limit, offset });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/predictions', async (req, res) => {
  const { id, type, title, subtitle, predictedResult, actualResult, outcome, details } = req.body;
  if (!id || !type || !title || !predictedResult)
    return res.status(400).json({ error: 'id, type, title, predictedResult required' });
  try {
    await pool.execute(
      `INSERT INTO prediction_logs
         (id, type, title, subtitle, predicted_result, actual_result, outcome, details)
       VALUES (?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         actual_result  = COALESCE(VALUES(actual_result), actual_result),
         outcome        = VALUES(outcome),
         details        = VALUES(details),
         updated_at     = NOW()`,
      [id, type, title, subtitle || '', predictedResult,
       actualResult || null, outcome || 'pending', json(details)]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/predictions/batch', async (req, res) => {
  const { logs } = req.body;
  if (!Array.isArray(logs)) return res.status(400).json({ error: 'logs array required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const l of logs) {
      await conn.execute(
        `INSERT INTO prediction_logs
           (id, type, title, subtitle, predicted_result, actual_result, outcome, details)
         VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           actual_result  = COALESCE(VALUES(actual_result), actual_result),
           outcome        = VALUES(outcome),
           details        = VALUES(details),
           updated_at     = NOW()`,
        [l.id, l.type, l.title, l.subtitle || '', l.predictedResult,
         l.actualResult || null, l.outcome || 'pending', json(l.details)]
      );
    }
    await conn.commit();
    res.json({ success: true, count: logs.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

app.patch('/api/predictions/report-lottery', async (req, res) => {
  const { byDate, lotteryType } = req.body;
  if (!byDate) return res.status(400).json({ error: 'byDate required' });
  try {
    for (const [date, nums] of Object.entries(byDate)) {
      const actualStr = nums.map(n => String(n).padStart(2,'0')).join(' ');
      let sql = `UPDATE prediction_logs
                 SET actual_result = ?, outcome = 'correct', updated_at = NOW()
                 WHERE outcome = 'pending'
                   AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.drawNo')) REGEXP ?`;
      const params = [actualStr, date.replace('/', '\\/') + '$'];
      if (lotteryType) {
        sql += ` AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.lotteryType')) = ?`;
        params.push(lotteryType);
      }
      await pool.execute(sql, params);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 539 開獎記錄
// ════════════════════════════════════════════════════════════════

app.get('/api/lottery/539', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY draw_date DESC LIMIT 80'
    );
    res.json(rows.map(r => ({ date: r.draw_date, numbers: parse(r.numbers) })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lottery/539/bulk', async (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records)) return res.status(400).json({ error: 'records array required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const r of records) {
      await conn.execute(
        `INSERT INTO lottery_draws_539 (draw_date, numbers) VALUES (?,?)
         ON DUPLICATE KEY UPDATE numbers = VALUES(numbers)`,
        [r.date, json(r.numbers)]
      );
    }
    await conn.commit();
    res.json({ success: true, count: records.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally { conn.release(); }
});

// ════════════════════════════════════════════════════════════════
// 大樂透開獎記錄
// ════════════════════════════════════════════════════════════════

app.get('/api/lottery/lotto', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT draw_date, numbers FROM lottery_draws_lotto ORDER BY draw_date DESC LIMIT 200'
    );
    res.json(rows.map(r => ({ date: r.draw_date, numbers: parse(r.numbers) })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lottery/lotto/bulk', async (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records)) return res.status(400).json({ error: 'records required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const r of records) {
      await conn.execute(
        `INSERT INTO lottery_draws_lotto (draw_date, numbers) VALUES (?,?)
         ON DUPLICATE KEY UPDATE numbers = VALUES(numbers)`,
        [r.date, json(r.numbers)]
      );
    }
    await conn.commit();
    res.json({ success: true, count: records.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally { conn.release(); }
});

// ════════════════════════════════════════════════════════════════
// 威力彩開獎記錄
// ════════════════════════════════════════════════════════════════

app.get('/api/lottery/power', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT draw_date, numbers FROM lottery_draws_power ORDER BY draw_date DESC LIMIT 200'
    );
    res.json(rows.map(r => ({ date: r.draw_date, numbers: parse(r.numbers) })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/lottery/power/bulk', async (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records)) return res.status(400).json({ error: 'records required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const r of records) {
      await conn.execute(
        `INSERT INTO lottery_draws_power (draw_date, numbers) VALUES (?,?)
         ON DUPLICATE KEY UPDATE numbers = VALUES(numbers)`,
        [r.date, json(r.numbers)]
      );
    }
    await conn.commit();
    res.json({ success: true, count: records.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally { conn.release(); }
});

// ════════════════════════════════════════════════════════════════
// 賓果賓果開獎
// ════════════════════════════════════════════════════════════════

app.get('/api/bingo/draws', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '100'), 500);
  try {
    const [rows] = await pool.query(
      `SELECT draw_no, numbers, draw_time FROM bingo_draws ORDER BY draw_no DESC LIMIT ${limit}`
    );
    res.json(rows.map(r => ({
      drawNo: r.draw_no,
      numbers: parse(r.numbers),
      drawTime: r.draw_time,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bingo/draws', async (req, res) => {
  const { drawNo, numbers, drawTime } = req.body;
  if (!drawNo || !numbers) return res.status(400).json({ error: 'drawNo, numbers required' });
  try {
    await pool.execute(
      `INSERT INTO bingo_draws (draw_no, numbers, draw_time) VALUES (?,?,?)
       ON DUPLICATE KEY UPDATE numbers = VALUES(numbers), draw_time = VALUES(draw_time)`,
      [drawNo, json(numbers), drawTime || null]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/bingo/draws/batch', async (req, res) => {
  const { draws } = req.body;
  if (!Array.isArray(draws)) return res.status(400).json({ error: 'draws array required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const d of draws) {
      await conn.execute(
        `INSERT INTO bingo_draws (draw_no, numbers, draw_time) VALUES (?,?,?)
         ON DUPLICATE KEY UPDATE numbers = VALUES(numbers)`,
        [d.drawNo, json(d.numbers), d.drawTime || null]
      );
    }
    await conn.commit();
    res.json({ success: true, count: draws.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally { conn.release(); }
});

// ════════════════════════════════════════════════════════════════
// 體育比賽
// ════════════════════════════════════════════════════════════════

app.get('/api/sports/matches', async (req, res) => {
  const { sport, status, limit = 100 } = req.query;
  try {
    let sql = 'SELECT * FROM sports_matches WHERE 1=1';
    const params = [];
    if (sport)  { sql += ' AND sport_type = ?'; params.push(sport); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY match_time DESC LIMIT ?';
    params.push(parseInt(limit));
    const [rows] = await pool.execute(sql, params);
    res.json(rows.map(r => ({
      ...r,
      odds_data:  parse(r.odds_data),
      prediction: parse(r.prediction),
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sports/matches', async (req, res) => {
  const { id, homeTeam, awayTeam, league, sportType, matchTime,
          homeScore, awayScore, status, oddsData, prediction } = req.body;
  if (!id || !homeTeam || !awayTeam) return res.status(400).json({ error: 'id, homeTeam, awayTeam required' });
  try {
    await pool.execute(
      `INSERT INTO sports_matches
         (id, home_team, away_team, league, sport_type, match_time,
          home_score, away_score, status, odds_data, prediction)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         home_score  = COALESCE(VALUES(home_score), home_score),
         away_score  = COALESCE(VALUES(away_score), away_score),
         status      = VALUES(status),
         odds_data   = VALUES(odds_data),
         prediction  = VALUES(prediction),
         updated_at  = NOW()`,
      [id, homeTeam, awayTeam, league || '', sportType || '', matchTime || null,
       homeScore ?? null, awayScore ?? null, status || 'scheduled',
       json(oddsData), json(prediction)]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 批次儲存 ESPN 比賽（每次載入後自動備份到 MySQL）
app.post('/api/sports/matches/batch', async (req, res) => {
  const { matches } = req.body;
  if (!Array.isArray(matches) || matches.length === 0)
    return res.status(400).json({ error: 'matches must be non-empty array' });
  try {
    let saved = 0;
    for (const m of matches) {
      const { id, homeTeam, awayTeam, league, sportType, matchTime,
              homeScore, awayScore, status, oddsData, prediction } = m;
      if (!id || !homeTeam || !awayTeam) continue;
      await pool.execute(
        `INSERT INTO sports_matches
           (id, home_team, away_team, league, sport_type, match_time,
            home_score, away_score, status, odds_data, prediction)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           home_score  = COALESCE(VALUES(home_score), home_score),
           away_score  = COALESCE(VALUES(away_score), away_score),
           status      = VALUES(status),
           odds_data   = IF(VALUES(odds_data) IS NOT NULL, VALUES(odds_data), odds_data),
           prediction  = IF(VALUES(prediction) IS NOT NULL, VALUES(prediction), prediction),
           updated_at  = NOW()`,
        [id, homeTeam, awayTeam, league || '', sportType || '', matchTime || null,
         homeScore ?? null, awayScore ?? null, status || 'scheduled',
         json(oddsData), json(prediction)]
      );
      saved++;
    }
    res.json({ success: true, saved });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 歷史預測準確率校準資料（供 Flutter 預測引擎用）
app.get('/api/sports/calibration', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT league, sport_type,
              COUNT(*) AS total,
              SUM(CASE
                WHEN home_score IS NOT NULL AND away_score IS NOT NULL
                 AND JSON_UNQUOTE(JSON_EXTRACT(prediction, '$.winner')) = 'home'
                 AND home_score > away_score THEN 1
                WHEN home_score IS NOT NULL AND away_score IS NOT NULL
                 AND JSON_UNQUOTE(JSON_EXTRACT(prediction, '$.winner')) = 'away'
                 AND away_score > home_score THEN 1
                WHEN home_score IS NOT NULL AND away_score IS NOT NULL
                 AND JSON_UNQUOTE(JSON_EXTRACT(prediction, '$.winner')) = 'draw'
                 AND home_score = away_score THEN 1
                ELSE 0 END) AS correct_count,
              SUM(CASE WHEN home_score IS NOT NULL AND away_score IS NOT NULL
                   AND JSON_EXTRACT(prediction, '$.winner') IS NOT NULL THEN 1
                   ELSE 0 END) AS judged_count,
              AVG(CASE WHEN home_score IS NOT NULL THEN home_score ELSE NULL END) AS avg_home_actual,
              AVG(CASE WHEN away_score IS NOT NULL THEN away_score ELSE NULL END) AS avg_away_actual,
              AVG(CASE WHEN home_score IS NOT NULL AND JSON_EXTRACT(prediction, '$.predictedHome') IS NOT NULL
                   THEN JSON_EXTRACT(prediction, '$.predictedHome') ELSE NULL END) AS avg_pred_home,
              AVG(CASE WHEN away_score IS NOT NULL AND JSON_EXTRACT(prediction, '$.predictedAway') IS NOT NULL
                   THEN JSON_EXTRACT(prediction, '$.predictedAway') ELSE NULL END) AS avg_pred_away
       FROM sports_matches
       WHERE match_time > DATE_SUB(NOW(), INTERVAL 90 DAY)
       GROUP BY league, sport_type
       HAVING total >= 3`
    );
    const calibration = {};
    for (const r of rows) {
      const key = r.league || r.sport_type;
      const accuracy = r.judged_count > 0 ? r.correct_count / r.judged_count : null;
      // 實際進球 / 預測進球 → 修正係數（偏低則放大，偏高則縮小）
      const homeScoreBias = (r.avg_home_actual && r.avg_pred_home && r.avg_pred_home > 0.05)
        ? Math.min(Math.max(r.avg_home_actual / r.avg_pred_home, 0.60), 1.80) : 1.0;
      const awayScoreBias = (r.avg_away_actual && r.avg_pred_away && r.avg_pred_away > 0.05)
        ? Math.min(Math.max(r.avg_away_actual / r.avg_pred_away, 0.60), 1.80) : 1.0;
      calibration[key] = {
        league: r.league, sport: r.sport_type,
        total: r.total, judged: r.judged_count,
        accuracy, homeScoreBias, awayScoreBias,
      };
    }
    res.json(calibration);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 報紙 539 分析資料
// ════════════════════════════════════════════════════════════════

app.get('/api/newspaper/539', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM newspaper_539 ORDER BY draw_date DESC LIMIT 60'
    );
    res.json(rows.map(r => ({
      date:      r.draw_date,
      guZhi:     r.gu_zhi,
      erZhong:   parse(r.er_zhong),
      sanZhong:  parse(r.san_zhong),
      xique:     parse(r.xique),
      tiangan:   parse(r.tiangan),
      bagua:     parse(r.bagua),
      banlu:     parse(r.banlu),
      toucai1:   parse(r.toucai1),
      toucai2:   parse(r.toucai2),
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/newspaper/539/bulk', async (req, res) => {
  const { entries } = req.body;
  if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries array required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const e of entries) {
      await conn.execute(
        `INSERT INTO newspaper_539
           (draw_date, gu_zhi, er_zhong, san_zhong, xique, tiangan, bagua, banlu, toucai1, toucai2)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           gu_zhi=VALUES(gu_zhi), er_zhong=VALUES(er_zhong), san_zhong=VALUES(san_zhong),
           xique=VALUES(xique), tiangan=VALUES(tiangan), bagua=VALUES(bagua),
           banlu=VALUES(banlu), toucai1=VALUES(toucai1), toucai2=VALUES(toucai2)`,
        [e.date, e.guZhi, json(e.erZhong), json(e.sanZhong),
         json(e.xique), json(e.tiangan), json(e.bagua), json(e.banlu),
         json(e.toucai1), json(e.toucai2)]
      );
    }
    await conn.commit();
    res.json({ success: true, count: entries.length });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally { conn.release(); }
});

// ════════════════════════════════════════════════════════════════
// AI 自我學習策略
// ════════════════════════════════════════════════════════════════

app.get('/api/learning/:category', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT strategy, weights, hit_records FROM learning_weights WHERE category = ?',
      [req.params.category]
    );
    if (!rows.length) return res.json({ strategy: 'balanced', weights: {}, hitRecords: [] });
    const r = rows[0];
    res.json({
      strategy: r.strategy,
      weights:  parse(r.weights),
      hitRecords: parse(r.hit_records) || [],
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/learning/:category', async (req, res) => {
  const { strategy, weights, hitRecord } = req.body;
  try {
    const [rows] = await pool.execute(
      'SELECT hit_records FROM learning_weights WHERE category = ?', [req.params.category]
    );
    let records = rows.length ? (parse(rows[0].hit_records) || []) : [];
    if (hitRecord) {
      records.push({ ...hitRecord, ts: new Date().toISOString() });
      records = records.slice(-100);
    }
    await pool.execute(
      `INSERT INTO learning_weights (category, strategy, weights, hit_records)
       VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE
         strategy = VALUES(strategy), weights = VALUES(weights),
         hit_records = VALUES(hit_records), updated_at = NOW()`,
      [req.params.category, strategy || 'balanced', json(weights || {}), json(records)]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 圖表分析快取
// ════════════════════════════════════════════════════════════════

app.get('/api/chart/:type', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT data FROM chart_cache WHERE chart_type = ? AND expires_at > NOW()',
      [req.params.type]
    );
    if (!rows.length) return res.status(404).json({ expired: true });
    res.json(parse(rows[0].data));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/chart/:type', async (req, res) => {
  const { data, ttlMinutes = 60 } = req.body;
  try {
    await pool.execute(
      `INSERT INTO chart_cache (chart_type, data, expires_at)
       VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE))
       ON DUPLICATE KEY UPDATE
         data = VALUES(data), expires_at = VALUES(expires_at)`,
      [req.params.type, json(data), ttlMinutes]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 統計總覽（dashboard）
// ════════════════════════════════════════════════════════════════

app.get('/api/stats', async (req, res) => {
  try {
    const [[{ total539 }]]    = await pool.execute('SELECT COUNT(*) AS total539 FROM lottery_draws_539');
    const [[{ totalLotto }]]  = await pool.execute('SELECT COUNT(*) AS totalLotto FROM lottery_draws_lotto');
    const [[{ totalPower }]]  = await pool.execute('SELECT COUNT(*) AS totalPower FROM lottery_draws_power');
    const [[{ totalBingo }]]  = await pool.execute('SELECT COUNT(*) AS totalBingo FROM bingo_draws');
    const [[{ totalMatches }]]= await pool.execute('SELECT COUNT(*) AS totalMatches FROM sports_matches');
    const [[{ totalPreds }]]  = await pool.execute('SELECT COUNT(*) AS totalPreds FROM prediction_logs');
    const [[{ totalUsers }]]  = await pool.execute('SELECT COUNT(*) AS totalUsers FROM users');
    res.json({
      lottery539: total539, lotto: totalLotto, power: totalPower,
      bingo: totalBingo, matches: totalMatches, predictions: totalPreds, users: totalUsers,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// ECPay 綠界金流
// ════════════════════════════════════════════════════════════════

const ECPAY_URL = process.env.ECPAY_TEST_MODE === 'true'
  ? 'https://payment-stage.ecpay.com.tw/Cashier/AioCheckOut/V5'
  : 'https://payment.ecpay.com.tw/Cashier/AioCheckOut/V5';

const PLANS = {
  1:  { name: '1個月試用體驗方案',  amount: 290  },
  3:  { name: '3個月精準獲利方案',  amount: 750  },
  6:  { name: '6個月數據贏家方案',  amount: 1290 },
  12: { name: '12個月全年制霸方案', amount: 1990 },
};

app.post('/api/payment/create', async (req, res) => {
  const { email, months } = req.body;
  if (!email || !PLANS[months]) return res.status(400).json({ error: 'email, months(1/3/6/12) required' });

  const plan     = PLANS[months];
  const tradeNo  = 'PP' + Date.now();
  const tradeDate = new Date().toLocaleString('zh-TW', {
    timeZone: 'Asia/Taipei', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  }).replace(/\//g, '/').replace(',', '');

  const params = {
    MerchantID:        process.env.ECPAY_MERCHANT_ID || '2000132',
    MerchantTradeNo:   tradeNo,
    MerchantTradeDate: tradeDate,
    PaymentType:       'aio',
    TotalAmount:       plan.amount,
    TradeDesc:         '胖胖體育訂閱',
    ItemName:          plan.name,
    ReturnURL:         process.env.ECPAY_RETURN_URL,
    ClientBackURL:     process.env.ECPAY_RETURN_URL?.replace('/callback', '/result') || '',
    ChoosePayment:     'ALL',
    EncryptType:       1,
  };

  params.CheckMacValue = ecpayCheckMac(
    params,
    process.env.ECPAY_HASH_KEY,
    process.env.ECPAY_HASH_IV
  );

  await pool.execute(
    `INSERT INTO payment_orders (order_no, user_email_enc, plan_name, amount, months)
     VALUES (?,?,?,?,?)`,
    [tradeNo, encrypt(email), plan.name, plan.amount, months]
  ).catch(() => {});

  const formFields = Object.entries(params)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${v}">`)
    .join('\n');
  const html = `<!DOCTYPE html><html><body>
    <form id="f" method="POST" action="${ECPAY_URL}">${formFields}</form>
    <script>document.getElementById('f').submit();</script>
  </body></html>`;

  res.json({ orderNo: tradeNo, ecpayUrl: ECPAY_URL, html, params });
});

app.post('/api/payment/callback', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const data = { ...req.body };
    const receivedMac = data.CheckMacValue;
    delete data.CheckMacValue;

    const expected = ecpayCheckMac(data, process.env.ECPAY_HASH_KEY, process.env.ECPAY_HASH_IV);
    if (receivedMac?.toUpperCase() !== expected) {
      console.error('❌ ECPay CheckMacValue 不符');
      return res.send('0|ErrorMessage');
    }

    const { MerchantTradeNo, RtnCode, TradeNo } = req.body;
    if (RtnCode === '1') {
      await pool.execute(
        `UPDATE payment_orders
         SET status='paid', ecpay_trade_no=?, paid_at=NOW()
         WHERE order_no=?`,
        [TradeNo, MerchantTradeNo]
      );
      const [[order]] = await pool.execute(
        'SELECT user_email_enc, months FROM payment_orders WHERE order_no=?',
        [MerchantTradeNo]
      );
      if (order) {
        const email   = decrypt(order.user_email_enc);
        const expires = new Date();
        expires.setMonth(expires.getMonth() + order.months);
        await pool.execute(
          `INSERT INTO users (email, auth_expires_at)
           VALUES (?, ?) ON DUPLICATE KEY UPDATE auth_expires_at=?, is_active=TRUE, updated_at=NOW()`,
          [email, expires, expires]
        );
        console.log(`✅ 訂閱開通 ${email} 到 ${expires.toISOString()}`);
      }
    }
    res.send('1|OK');
  } catch (e) {
    console.error('ECPay callback error:', e);
    res.send('0|ServerError');
  }
});

app.get('/api/payment/order/:orderNo', async (req, res) => {
  try {
    const [[row]] = await pool.execute(
      `SELECT order_no, plan_name, amount, months, status, paid_at, created_at
       FROM payment_orders WHERE order_no=?`,
      [req.params.orderNo]
    );
    if (!row) return res.status(404).json({ error: 'Order not found' });
    res.json(row);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 管理：查詢所有訂單（需要 Admin Key）
app.get('/api/admin/orders', requireAdminKey, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT order_no, plan_name, amount, months, status, paid_at, created_at,
              user_email_enc FROM payment_orders ORDER BY created_at DESC LIMIT 100`
    );
    const result = rows.map(r => ({
      ...r, email: decrypt(r.user_email_enc), user_email_enc: undefined,
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 管理：查詢所有用戶（需要 Admin Key）
app.get('/api/admin/users', requireAdminKey, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, email, auth_expires_at, is_active, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 拖牌 / 539 分析結果同步
// ════════════════════════════════════════════════════════════════

app.post('/api/lottery/drag-patterns', async (req, res) => {
  const { patterns } = req.body;
  if (!Array.isArray(patterns)) return res.status(400).json({ error: 'patterns array required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const p of patterns) {
      await conn.execute(
        `INSERT INTO drag_patterns_539 (drag_number, interval_avg, current_gap, is_due_next, hit_rate)
         VALUES (?,?,?,?,?)
         ON DUPLICATE KEY UPDATE
           interval_avg=VALUES(interval_avg), current_gap=VALUES(current_gap),
           is_due_next=VALUES(is_due_next), hit_rate=VALUES(hit_rate), updated_at=NOW()`,
        [p.drag, p.interval || 0, p.currentGap || 0, p.isDueNext || false, p.hitRate || 0]
      );
    }
    await conn.commit();
    res.json({ success: true, count: patterns.length });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: e.message }); }
  finally { conn.release(); }
});

app.get('/api/lottery/drag-patterns', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT drag_number, interval_avg, current_gap, is_due_next, hit_rate FROM drag_patterns_539 ORDER BY drag_number'
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 連戰疲勞 (sports_rest_games)
// ════════════════════════════════════════════════════════════════

app.post('/api/sports/rest-games', async (req, res) => {
  const { team, sport, restDays, lastGame } = req.body;
  if (!team || !sport) return res.status(400).json({ error: 'team, sport required' });
  try {
    await pool.execute(
      `INSERT INTO sports_rest_games (team, sport, rest_days, last_game)
       VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE rest_days=VALUES(rest_days), last_game=VALUES(last_game), updated_at=NOW()`,
      [team, sport, restDays || 0, lastGame || null]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sports/rest-games', async (req, res) => {
  const { sport } = req.query;
  try {
    let sql = 'SELECT * FROM sports_rest_games';
    const params = [];
    if (sport) { sql += ' WHERE sport=?'; params.push(sport); }
    sql += ' ORDER BY rest_days DESC';
    const [rows] = await pool.execute(sql, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 大樂透 / 威力彩 開獎資料端點（抓取 pilio.idv.tw）
// ════════════════════════════════════════════════════════════════

function fetchHtml(url) {
  return new Promise((resolve) => {
    https.get(url, {
      headers: {
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Encoding': 'identity',
        'User-Agent': 'Mozilla/5.0 (compatible; PangPang/1.0)',
      }
    }, (res) => {
      // Handle redirect
      if (res.statusCode === 301 || res.statusCode === 302) {
        const loc = res.headers.location;
        if (loc) { fetchHtml(loc).then(resolve); return; }
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(Buffer.concat(chunks).toString('utf8'));
        } catch { resolve(''); }
      });
    }).on('error', () => resolve(''));
  });
}

function parseLotteryHtml(html, isLtoBig) {
  // pilio.idv.tw 結構：
  //   <td class="date-cell">MM/DD<br>期數(星期)</td>
  //   <td class="number-cell"> 04,&nbsp;12,&nbsp;28,... </td>
  //   <td class="bonus-cell">38</td>
  const records = [];
  const rowPattern = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  let rowMatch;

  while ((rowMatch = rowPattern.exec(html)) !== null) {
    const row = rowMatch[1];

    // 找日期欄（內容如 06/19<br>26(五)，取 <br> 前的 MM/DD）
    const dateM = row.match(/class="date-cell"[^>]*>([\s\S]*?)<\/td>/i);
    const date = dateM
      ? dateM[1].replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, '')
          .replace(/&nbsp;/g, ' ').trim().split(/\s/)[0]
      : '';

    // 找號碼欄（所有號碼逗號分隔）
    const numM = row.match(/class="number-cell"[^>]*>([\s\S]*?)<\/td>/i);
    const numbers = numM
      ? numM[1].replace(/&nbsp;/g, ' ').replace(/<[^>]+>/g, '').split(',')
          .map(s => parseInt(s.trim()))
          .filter(n => !isNaN(n) && n >= 1 && n <= (isLtoBig ? 49 : 38))
      : [];

    // 找特別號
    const bonusM = row.match(/class="bonus-cell"[^>]*>([\s\S]*?)<\/td>/i);
    const special = bonusM ? parseInt(bonusM[1].replace(/<[^>]+>/g, '').trim()) : null;

    if (numbers.length >= 6) {
      records.push({
        date: date || '',
        numbers: numbers.slice(0, 6).sort((a, b) => a - b),
        special: isNaN(special) ? null : special,
      });
    }
  }

  // 若 class 解析失敗，回退到舊版 cell-by-cell 解析
  if (records.length === 0) {
    const fallbackRows = [];
    const trPat = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
    let tm;
    while ((tm = trPat.exec(html)) !== null) {
      const cells = [];
      const tdPat = /<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi;
      let cm;
      while ((cm = tdPat.exec(tm[1])) !== null) {
        cells.push(cm[1].replace(/<[^>]+>/g, '').replace(/&nbsp;/g, ' ').trim());
      }
      if (cells.length >= 3) fallbackRows.push(cells);
    }
    for (const cells of fallbackRows) {
      const allNums = [];
      let date = '';
      for (let i = 0; i < cells.length; i++) {
        const cell = cells[i].trim();
        if (/\d{2}\/\d{2}/.test(cell)) date = cell.split(/\s/)[0];
        // 逗號分隔的號碼格
        if (cell.includes(',')) {
          cell.split(',').forEach(s => {
            const n = parseInt(s.trim());
            if (!isNaN(n) && n >= 1 && n <= (isLtoBig ? 49 : 38)) allNums.push(n);
          });
        } else {
          const n = parseInt(cell);
          if (!isNaN(n) && n >= 1 && n <= (isLtoBig ? 49 : 38)) allNums.push(n);
        }
      }
      if (allNums.length >= 6) {
        records.push({ date, numbers: allNums.slice(0, 6).sort((a, b) => a - b), special: allNums[6] || null });
      }
    }
  }

  return records.slice(0, 30);
}

// In-memory cache for lottery data (30 min TTL)
const _lotteryCache = { ltoBig: null, lto: null, ltoBigTime: 0, ltoTime: 0 };

app.get('/api/lottery/lto-data', async (req, res) => {
  const type = req.query.type || 'ltobig'; // 'ltobig' or 'lto'
  const isLtoBig = type === 'ltobig';
  const url = isLtoBig
    ? 'https://www.pilio.idv.tw/ltobig/list.asp'
    : 'https://www.pilio.idv.tw/lto/list.asp';
  const cacheKey = isLtoBig ? 'ltoBig' : 'lto';
  const cacheTimeKey = isLtoBig ? 'ltoBigTime' : 'ltoTime';

  const now = Date.now();
  if (_lotteryCache[cacheKey] && now - _lotteryCache[cacheTimeKey] < 30 * 60 * 1000) {
    return res.json({ ok: true, records: _lotteryCache[cacheKey], cached: true });
  }

  try {
    const html = await fetchHtml(url);
    if (!html) { return res.json({ ok: false, records: [], error: 'fetch failed' }); }
    const records = parseLotteryHtml(html, isLtoBig);
    _lotteryCache[cacheKey] = records;
    _lotteryCache[cacheTimeKey] = now;
    res.json({ ok: true, records, cached: false });
  } catch (e) {
    res.json({ ok: false, records: [], error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 足球戰術分析端點（ESPN 免費公開 API）
// ════════════════════════════════════════════════════════════════

/**
 * GET /api/football/team-analysis
 * Query: leaguePath (e.g. soccer/eng.1), homeTeamId, awayTeamId
 * 回傳兩隊本季統計、教練、近5場比分，用於正確比數預測
 */
app.get('/api/football/team-analysis', async (req, res) => {
  const { leaguePath, homeTeamId, awayTeamId } = req.query;
  if (!leaguePath || !homeTeamId || !awayTeamId) {
    return res.status(400).json({ error: 'leaguePath, homeTeamId, awayTeamId 為必填' });
  }

  const ESPN = 'https://site.api.espn.com/apis/site/v2/sports';

  // 6 個 ESPN 請求並行
  const [hStats, aStats, hTeam, aTeam, hSched, aSched] = await Promise.all([
    fetchJson(`${ESPN}/${leaguePath}/teams/${homeTeamId}/statistics`),
    fetchJson(`${ESPN}/${leaguePath}/teams/${awayTeamId}/statistics`),
    fetchJson(`${ESPN}/${leaguePath}/teams/${homeTeamId}`),
    fetchJson(`${ESPN}/${leaguePath}/teams/${awayTeamId}`),
    fetchJson(`${ESPN}/${leaguePath}/teams/${homeTeamId}/schedule`),
    fetchJson(`${ESPN}/${leaguePath}/teams/${awayTeamId}/schedule`),
  ]);

  function parseStat(statsData, name) {
    if (!statsData?.results) return null;
    for (const cat of statsData.results) {
      for (const stat of (cat.stats || [])) {
        if (stat.name === name) return parseFloat(stat.value) || null;
      }
    }
    return null;
  }

  function parseTeamProfile(statsData, teamData, schedData) {
    // 教練
    const coach = teamData?.team?.coaches?.[0]?.firstName
      ? `${teamData.team.coaches[0].firstName} ${teamData.team.coaches[0].lastName || ''}`.trim()
      : null;

    // 本季統計
    const goalsFor      = parseStat(statsData, 'goalsScoredFor')  ?? parseStat(statsData, 'goals')       ?? 0;
    const goalsAgainst  = parseStat(statsData, 'goalsScoredAgainst') ?? parseStat(statsData, 'goalsAgainst') ?? 0;
    const shotsPerGame  = parseStat(statsData, 'shotsPerGame')    ?? parseStat(statsData, 'shots')        ?? 0;
    const shotsPG       = parseStat(statsData, 'shotsOnTargetPerGame') ?? 0;
    const possessionPct = parseStat(statsData, 'possessionPct')   ?? parseStat(statsData, 'avgPossessionPct') ?? 50;
    const gamesPlayed   = parseStat(statsData, 'gamesPlayed')     ?? parseStat(statsData, 'appearances')  ?? 1;

    // 近5場有效比分（已結束且有比數的）
    const events = schedData?.events ?? [];
    const recentScores = [];
    for (const ev of events) {
      if (recentScores.length >= 5) break;
      const comp = ev.competitions?.[0];
      const status = comp?.status?.type?.completed;
      if (!status) continue;
      const comps = comp.competitors ?? [];
      if (comps.length < 2) continue;
      const home = comps.find(c => c.homeAway === 'home');
      const away = comps.find(c => c.homeAway === 'away');
      if (!home || !away) continue;
      recentScores.push({
        home: parseInt(home.score) || 0,
        away: parseInt(away.score) || 0,
        homeTeam: home.team?.abbreviation ?? '',
        awayTeam: away.team?.abbreviation ?? '',
        date: ev.date?.substring(0, 10) ?? '',
      });
    }

    // 戰術風格推斷
    const avgGoalsFor   = gamesPlayed > 0 ? goalsFor  / gamesPlayed : 0;
    const avgGoalsAgainst = gamesPlayed > 0 ? goalsAgainst / gamesPlayed : 0;
    let style = 'balanced';
    if (shotsPerGame >= 15 && possessionPct >= 55) style = 'possession-attack';
    else if (shotsPerGame >= 15 && possessionPct < 50) style = 'counter-attack';
    else if (shotsPerGame < 10 && avgGoalsAgainst < 0.9) style = 'defensive';
    else if (avgGoalsFor >= 2.0) style = 'high-scoring';

    return {
      coach,
      style,          // 戰術風格
      shotsPerGame:   Math.round(shotsPerGame * 10) / 10,
      shotsOnTarget:  Math.round(shotsPG * 10) / 10,
      possessionPct:  Math.round(possessionPct * 10) / 10,
      avgGoalsFor:    Math.round(avgGoalsFor * 100) / 100,
      avgGoalsAgainst:Math.round(avgGoalsAgainst * 100) / 100,
      gamesPlayed:    Math.round(gamesPlayed),
      recentScores,   // 近5場[{home,away,homeTeam,awayTeam,date}]
    };
  }

  res.json({
    home: parseTeamProfile(hStats, hTeam, hSched),
    away: parseTeamProfile(aStats, aTeam, aSched),
  });
});

// ════════════════════════════════════════════════════════════════
// 週報：自動計算並儲存各類別本週準確率
// ════════════════════════════════════════════════════════════════

app.post('/api/predictions/weekly-report', async (req, res) => {
  // 計算本週週一
  const now = new Date();
  const day = now.getDay(); // 0=Sun
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - (day === 0 ? 6 : day - 1));
  weekStart.setHours(0, 0, 0, 0);
  const weekStartStr = weekStart.toISOString().slice(0, 10);

  const categories = [
    { key: 'sport',         type: 'sport',   filter: null },
    { key: 'lottery_539',   type: 'lottery', filter: '539' },
    { key: 'lottery_lotto', type: 'lottery', filter: '大樂透' },
    { key: 'lottery_power', type: 'lottery', filter: '威力彩' },
    { key: 'bingo',         type: 'bingo',   filter: null },
  ];

  try {
    for (const cat of categories) {
      const sql = `SELECT outcome, details FROM prediction_logs WHERE type = ? AND created_at >= ?`;
      const [rows] = await pool.execute(sql, [cat.type, weekStartStr]);

      let filtered = rows;
      if (cat.filter) {
        filtered = rows.filter(r => {
          const d = parse(r.details);
          return (d && (d.lotteryType || '')).includes(cat.filter);
        });
      }

      const total   = filtered.length;
      const hit     = filtered.filter(r => r.outcome === 'correct').length;
      const partial = filtered.filter(r => r.outcome === 'partial').length;
      const miss    = filtered.filter(r => r.outcome === 'incorrect').length;
      const pending = filtered.filter(r => r.outcome === 'pending').length;
      const judged  = hit + partial + miss;
      const hitRate = judged > 0 ? (hit + partial * 0.5) / judged : 0;

      await pool.execute(
        `INSERT INTO prediction_weekly_summary
           (week_start, category, total_count, hit_count, partial_count, miss_count, pending_count, hit_rate)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           total_count   = VALUES(total_count),
           hit_count     = VALUES(hit_count),
           partial_count = VALUES(partial_count),
           miss_count    = VALUES(miss_count),
           pending_count = VALUES(pending_count),
           hit_rate      = VALUES(hit_rate),
           updated_at    = NOW()`,
        [weekStartStr, cat.key, total, hit, partial, miss, pending, hitRate]
      );
    }
    res.json({ ok: true, weekStart: weekStartStr });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/predictions/weekly-summary', async (req, res) => {
  const weeks = Math.min(parseInt(req.query.weeks || '4'), 52);
  try {
    const [rows] = await pool.execute(
      `SELECT * FROM prediction_weekly_summary ORDER BY week_start DESC LIMIT ${weeks * 5}`
    );
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 預測詳細分析紀錄
// ════════════════════════════════════════════════════════════════

app.post('/api/predictions/analysis-detail', async (req, res) => {
  const { logId, category, subCategory, homeTeam, awayTeam, sportType,
          drawDate, drawNo, predictedNums, actualNums, hitCount,
          signalBreakdown, confidence, outcome } = req.body;
  if (!logId || !category) return res.status(400).json({ error: 'logId and category required' });
  const expires = new Date(Date.now() + 8 * 24 * 60 * 60 * 1000);
  try {
    await pool.execute(
      `INSERT INTO prediction_analysis_detail
         (log_id, category, sub_category, home_team, away_team, sport_type,
          draw_date, draw_no, predicted_nums, actual_nums, hit_count,
          signal_breakdown, confidence, outcome, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE
         actual_nums      = COALESCE(VALUES(actual_nums), actual_nums),
         hit_count        = VALUES(hit_count),
         outcome          = VALUES(outcome),
         updated_at       = NOW()`,
      [logId, category, subCategory || '', homeTeam || '', awayTeam || '', sportType || '',
       drawDate || '', drawNo || 0,
       JSON.stringify(predictedNums || []), JSON.stringify(actualNums || []),
       hitCount || 0, JSON.stringify(signalBreakdown || {}), confidence || 0,
       outcome || 'pending', expires]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/predictions/analysis-detail', async (req, res) => {
  const { category } = req.query;
  const days = Math.min(parseInt(req.query.days || '7'), 90);
  try {
    const params = [days];
    let sql = `SELECT * FROM prediction_analysis_detail WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`;
    if (category) { sql += ' AND category = ?'; params.push(category); }
    sql += ' ORDER BY created_at DESC LIMIT 200';
    const [rows] = await pool.execute(sql, params);
    res.json(rows.map(r => ({
      ...r,
      predicted_nums:   parse(r.predicted_nums),
      actual_nums:      parse(r.actual_nums),
      signal_breakdown: parse(r.signal_breakdown),
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 定時任務（node-cron）
// ════════════════════════════════════════════════════════════════

function fetchJson(url) {
  return new Promise((resolve) => {
    https.get(url, { headers: { 'Accept': 'application/json' } }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

cron.schedule('20 13 * * *', async () => {
  console.log('⏰ 定時任務：同步最新彩券開獎資料...');
  const REPO = 'https://raw.githubusercontent.com/Boxing665/pang-pang-vip/main/data';
  try {
    for (const [key, table, url] of [
      ['records', 'lottery_draws_539',   `${REPO}/lotto539.json`],
      ['records', 'lottery_draws_lotto', `${REPO}/lotto_big.json`],
      ['records', 'lottery_draws_power', `${REPO}/lotto_power.json`],
    ]) {
      const data = await fetchJson(url);
      if (!data?.[key]?.length) continue;
      for (const r of data[key]) {
        await pool.execute(
          `INSERT INTO ${table} (draw_date, numbers) VALUES (?,?)
           ON DUPLICATE KEY UPDATE numbers=VALUES(numbers)`,
          [r.date, json(r.numbers)]
        ).catch(() => {});
      }
      console.log(`  ✅ ${table}: ${data[key].length} 筆同步完成`);
    }
  } catch (e) { console.error('定時同步失敗:', e.message); }
}, { timezone: 'Asia/Taipei' });

cron.schedule('0 3 * * *', async () => {
  await pool.execute('DELETE FROM chart_cache WHERE expires_at < NOW()').catch(() => {});
  console.log('🧹 過期快取已清除');
}, { timezone: 'Asia/Taipei' });

// ════════════════════════════════════════════════════════════════
// 賓果統計分析工具函式
// ════════════════════════════════════════════════════════════════

/** 從 bingo.kuaishou1688.com 抓取最新一批開獎 */
async function fetchBingoData(count = 10) {
  return new Promise((resolve) => {
    const postData = JSON.stringify({ count });
    const req = require('http').request(
      { hostname: 'bingo.kuaishou1688.com', path: '/api/get_data', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': postData.length } },
      (res) => { let b = ''; res.on('data', c => b += c); res.on('end', () => { try { resolve(JSON.parse(b)); } catch { resolve(null); } }); }
    );
    req.on('error', () => resolve(null));
    req.setTimeout(8000, () => { req.destroy(); resolve(null); });
    req.write(postData); req.end();
  });
}

/** 增量更新賓果轉移矩陣（前一期 prevNums → 當期 curNums） */
async function updateBingoTransition(prevNums, curNums) {
  if (!prevNums || prevNums.length === 0) return;
  const pairs = [];
  for (const f of prevNums) for (const t of curNums) pairs.push([f, t]);
  for (const chunk of [pairs]) {
    if (chunk.length === 0) continue;
    const placeholders = chunk.map(() => '(?,?,1)').join(',');
    const vals = chunk.flat();
    await pool.execute(
      `INSERT INTO bingo_transition_matrix (from_num, to_num, count) VALUES ${placeholders}
       ON DUPLICATE KEY UPDATE count = count + 1`,
      vals
    );
  }
  // 更新機率
  const froms = [...new Set(prevNums)];
  for (const f of froms) {
    const [[row]] = await pool.query(
      'SELECT SUM(count) as total FROM bingo_transition_matrix WHERE from_num=?', [f]
    );
    if (row.total > 0) {
      await pool.execute(
        'UPDATE bingo_transition_matrix SET probability = count / ? WHERE from_num = ?',
        [row.total, f]
      );
    }
  }
}

/** 增量更新賓果共現矩陣 */
async function updateBingoCooccurrence(nums) {
  const sorted = [...nums].sort((a, b) => a - b);
  const pairs  = [];
  for (let i = 0; i < sorted.length; i++)
    for (let j = i + 1; j < sorted.length; j++)
      pairs.push([sorted[i], sorted[j]]);
  if (pairs.length === 0) return;
  const placeholders = pairs.map(() => '(?,?,1)').join(',');
  await pool.execute(
    `INSERT INTO bingo_cooccurrence (num_a, num_b, count) VALUES ${placeholders}
     ON DUPLICATE KEY UPDATE count = count + 1`,
    pairs.flat()
  );
}

/** 增量更新賓果號碼統計 */
async function updateBingoNumberStats(newNums, drawNo) {
  const numSet = new Set(newNums);
  const drawn  = [];
  const missed = [];
  for (let n = 1; n <= 80; n++) (numSet.has(n) ? drawn : missed).push(n);

  // 被開出的號碼：重置 miss，++times_drawn
  if (drawn.length > 0) {
    await pool.execute(
      `UPDATE bingo_number_stats
       SET times_drawn  = times_drawn + 1,
           max_miss     = GREATEST(max_miss, current_miss),
           current_miss = 0,
           last_drawn_no = ?,
           total_draws  = total_draws + 1
       WHERE number IN (${drawn.map(() => '?').join(',')})`,
      [drawNo, ...drawn]
    );
  }
  // 未開出的號碼：++miss
  if (missed.length > 0) {
    await pool.execute(
      `UPDATE bingo_number_stats
       SET current_miss = current_miss + 1,
           max_miss     = GREATEST(max_miss, current_miss + 1),
           total_draws  = total_draws + 1
       WHERE number IN (${missed.map(() => '?').join(',')})`,
      missed
    );
  }
}

/** 從頭重建所有賓果分析表（啟動時或手動觸發） */
async function rebuildBingoAnalysis() {
  const [draws] = await pool.query(
    'SELECT draw_no, numbers FROM bingo_draws ORDER BY draw_no ASC'
  );
  if (draws.length === 0) { console.log('⚠️ bingo_draws 無資料，跳過 rebuild'); return; }

  const parsed   = draws.map(r => ({ drawNo: r.draw_no, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
  const total    = parsed.length;

  // 清空並初始化
  await pool.execute('DELETE FROM bingo_number_stats');
  await pool.execute('DELETE FROM bingo_transition_matrix');
  await pool.execute('DELETE FROM bingo_cooccurrence');
  const initVals = Array.from({ length: 80 }, (_, i) => [i + 1, 0, 0, 0, null, 0]);
  await pool.query(
    'INSERT INTO bingo_number_stats (number, times_drawn, current_miss, max_miss, last_drawn_no, total_draws) VALUES ?',
    [initVals]
  );

  // 計算 number_stats（單次掃描 O(draws × 80)）
  const nd = {};
  for (let n = 1; n <= 80; n++) nd[n] = { td: 0, cm: 0, mm: 0, ld: null, run: 0 };
  for (const { drawNo, numbers } of parsed) {
    const ns = new Set(numbers);
    for (let n = 1; n <= 80; n++) {
      const d = nd[n];
      if (ns.has(n)) { d.td++; if (d.run > d.mm) d.mm = d.run; d.run = 0; d.ld = drawNo; }
      else           { d.run++; }
    }
  }
  await Promise.all(Array.from({ length: 80 }, (_, i) => i + 1).map(n => {
    const d = nd[n]; const cm = d.run; if (cm > d.mm) d.mm = cm;
    return pool.execute(
      'UPDATE bingo_number_stats SET times_drawn=?,current_miss=?,max_miss=?,last_drawn_no=?,total_draws=? WHERE number=?',
      [d.td, cm, d.mm, d.ld, total, n]
    );
  }));

  // 計算 transition_matrix
  const transMap = {};
  for (let i = 1; i < parsed.length; i++) {
    for (const f of parsed[i - 1].numbers) {
      if (!transMap[f]) transMap[f] = {};
      for (const t of parsed[i].numbers)
        transMap[f][t] = (transMap[f][t] || 0) + 1;
    }
  }
  const transRows = [];
  for (const [f, toMap] of Object.entries(transMap)) {
    const tot = Object.values(toMap).reduce((s, c) => s + c, 0);
    for (const [t, c] of Object.entries(toMap))
      transRows.push([+f, +t, c, c / tot]);
  }
  for (const ch of [transRows.slice(0, 5000), transRows.slice(5000, 10000), transRows.slice(10000)]) {
    if (!ch.length) continue;
    await pool.query('INSERT INTO bingo_transition_matrix (from_num,to_num,count,probability) VALUES ?', [ch]);
  }

  // 計算 co-occurrence
  const coMap = {};
  for (const { numbers } of parsed) {
    const s = [...numbers].sort((a, b) => a - b);
    for (let a = 0; a < s.length; a++)
      for (let b = a + 1; b < s.length; b++) {
        const k = s[a] * 100 + s[b];
        coMap[k] = (coMap[k] || 0) + 1;
      }
  }
  const coRows = Object.entries(coMap).map(([k, c]) => [Math.floor(+k / 100), +k % 100, c]);
  for (let i = 0; i < coRows.length; i += 5000) {
    const ch = coRows.slice(i, i + 5000);
    if (ch.length) await pool.query('INSERT INTO bingo_cooccurrence (num_a,num_b,count) VALUES ?', [ch]);
  }

  console.log(`✅ 賓果 analysis rebuilt: ${total} 期, ${transRows.length} 轉移, ${coRows.length} 共現`);
}

/** 儲存賓果下一期預測 */
async function saveBingoPrediction() {
  try {
    const [rows] = await pool.query(
      'SELECT draw_no, numbers FROM bingo_draws ORDER BY draw_no DESC LIMIT 120'
    );
    if (rows.length === 0) return;
    const records  = rows.map(r => ({ drawNo: r.draw_no, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
    const nextNo   = records[0].drawNo + 1;
    const [exists] = await pool.query(
      'SELECT draw_no FROM bingo_prediction_results WHERE draw_no=?', [nextNo]
    );
    if (exists.length > 0) return; // 已儲存

    const work = records.slice(0, 60);
    const { buildStats, computePredictScores } = require('./routes/bingo_analyze');
    const { stats, rawFreq, N } = buildStats(work);
    const sc = computePredictScores(work, stats, rawFreq, N, 'balanced', {}, [], [], []);
    const recommended = sc.map((v, i) => [i, v]).slice(1)
      .sort((a, b) => b[1] - a[1]).slice(0, 20).map(([n]) => n).sort((a, b) => a - b);

    await pool.execute(
      'INSERT IGNORE INTO bingo_prediction_results (draw_no, predicted_numbers) VALUES (?,?)',
      [nextNo, JSON.stringify(recommended)]
    );
    console.log(`🔮 賓果預測已儲存 期號#${nextNo}: [${recommended.join(',')}]`);
  } catch (e) { console.error('saveBingoPrediction:', e.message); }
}

/** 抓取最新賓果開獎 → 存入 DB → 更新分析表 */
async function fetchAndUpdateBingo() {
  try {
    const data = await fetchBingoData(10);
    if (!data?.success || !Array.isArray(data.data)) return;

    for (const item of data.data) {
      const nums   = (item['一般獎號'] || []).map(n => parseInt(n)).filter(n => n >= 1 && n <= 80).sort((a, b) => a - b);
      const drawNo = parseInt(item['期數']);
      if (nums.length < 15 || !drawNo) continue;

      // 檢查是否已存在
      const [exists] = await pool.query(
        'SELECT draw_no FROM bingo_draws WHERE draw_no=?', [drawNo]
      );
      if (exists.length > 0) continue; // 已有，跳過

      // 取前一期號碼（用於轉移矩陣）
      const [prevRows] = await pool.query(
        'SELECT numbers FROM bingo_draws ORDER BY draw_no DESC LIMIT 1'
      );
      const prevNums = prevRows.length > 0 ? Array.isArray(prevRows[0].numbers)?prevRows[0].numbers:JSON.parse(prevRows[0].numbers) : [];

      // 寫入 bingo_draws
      await pool.execute(
        'INSERT IGNORE INTO bingo_draws (draw_no, numbers, draw_time) VALUES (?,?,?)',
        [drawNo, JSON.stringify(nums), item['開獎日期'] ? `${item['開獎日期']} ${item['開獎時間']}` : null]
      );

      // 更新分析表
      await updateBingoNumberStats(nums, drawNo);
      await updateBingoTransition(prevNums, nums);
      await updateBingoCooccurrence(nums);

      // 更新預測結果對照
      const [pred] = await pool.query(
        'SELECT predicted_numbers FROM bingo_prediction_results WHERE draw_no=?', [drawNo]
      );
      if (pred.length > 0) {
        const predicted = Array.isArray(pred[0].predicted_numbers)?pred[0].predicted_numbers:JSON.parse(pred[0].predicted_numbers);
        const hitCount  = nums.filter(n => predicted.includes(n)).length;
        await pool.execute(
          'UPDATE bingo_prediction_results SET actual_numbers=?, hit_count=? WHERE draw_no=?',
          [JSON.stringify(nums), hitCount, drawNo]
        );
        console.log(`🎯 賓果對獎 #${drawNo}: 命中 ${hitCount}/20`);
      }

      console.log(`✅ 賓果新期 #${drawNo}: [${nums.slice(0, 5).join(',')}...] 已儲存`);
    }
  } catch (e) { console.error('fetchAndUpdateBingo:', e.message); }
}

// ── 賓果定時任務：每 5 分鐘存預測，30 秒後抓結果 ───────────────────────────
cron.schedule('*/5 * * * *', async () => {
  await saveBingoPrediction();
  setTimeout(() => fetchAndUpdateBingo(), 30000);
});

// ════════════════════════════════════════════════════════════════
// 539 自動開獎抓取 + 對獎
// ════════════════════════════════════════════════════════════════

/** 解析 pilio.idv.tw lto539 list 頁面，回傳 [{date:'MM/DD', numbers:[...]}]
 *  策略 A：優先用 class="date-cell"/"number-cell"（原結構）
 *  策略 B：fallback — 直接用 regex 找民國年/月/日 + 五個數字（更耐改版）
 */
function parse539Html(html) {
  const records = [];

  // ── 策略 A：結構化 class 解析 ─────────────────────────────────
  const rowPat = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  let rowM;
  while ((rowM = rowPat.exec(html)) !== null) {
    const row = rowM[1];
    const dateM = row.match(/class="date-cell"[^>]*>([\s\S]*?)<\/td>/i);
    const date = dateM
      ? dateM[1].replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, '')
          .replace(/&nbsp;/g, ' ').trim().split(/\s/)[0]
      : '';
    if (!date || !/^\d{2}\/\d{2}$/.test(date)) continue;

    const numM = row.match(/class="number-cell"[^>]*>([\s\S]*?)<\/td>/i);
    const numbers = numM
      ? numM[1].replace(/&nbsp;/g, ' ').replace(/<[^>]+>/g, '').split(',')
          .map(s => parseInt(s.trim())).filter(n => !isNaN(n) && n >= 1 && n <= 39)
      : [];
    if (numbers.length === 5) records.push({ date, numbers: numbers.sort((a, b) => a - b) });
  }

  if (records.length > 0) return records;

  // ── 策略 B：regex fallback（民國年/月/日 + 5 球） ────────────
  // 例：114/08/24 … 05 12 22 31 38
  const reB = /(\d{3})\/(\d{2})\/(\d{2})[^<]{0,200}?(\d{1,2})\D+(\d{1,2})\D+(\d{1,2})\D+(\d{1,2})\D+(\d{1,2})/g;
  let mB;
  const seenB = new Set();
  while ((mB = reB.exec(html)) !== null) {
    const month = mB[2];
    const day   = mB[3];
    const date  = `${month}/${day}`;
    if (seenB.has(date)) continue;
    const nums = [mB[4], mB[5], mB[6], mB[7], mB[8]]
      .map(Number).filter(n => n >= 1 && n <= 39);
    if (nums.length === 5) {
      seenB.add(date);
      records.push({ date, numbers: nums.sort((a, b) => a - b) });
    }
    if (records.length >= 60) break;
  }

  if (records.length > 0) return records;

  // ── 策略 C：pilio 新格式 "MM/DD YY(星期) n1, n2, n3, n4, n5" ──
  // TR 格式例：08/25 26(二) 08, 21, 23, 30, 35
  const rowPatC = /<tr[^>]*>([\s\S]*?)<\/tr>/gi;
  const seenC = new Set();
  rowPatC.lastIndex = 0;
  let rowMC;
  while ((rowMC = rowPatC.exec(html)) !== null) {
    const cell = rowMC[1]
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    // 找 MM/DD 日期
    const dateMC = cell.match(/\b(\d{2})\/(\d{2})\b/);
    if (!dateMC) continue;
    const mm = parseInt(dateMC[1]), dd = parseInt(dateMC[2]);
    if (mm < 1 || mm > 12 || dd < 1 || dd > 31) continue;
    const date = `${dateMC[1]}/${dateMC[2]}`;
    if (seenC.has(date)) continue;
    // 跳過日期後的 "YY(星期)" 如 "26(二)"
    let rest = cell.slice(dateMC.index + dateMC[0].length);
    rest = rest.replace(/^\s*\d{2}\([^)]*\)/, '');
    // 提取 1-39 的號碼
    const nums = [];
    const numRe = /\b(\d{1,2})\b/g;
    let nm;
    while ((nm = numRe.exec(rest)) !== null) {
      const n = parseInt(nm[1]);
      if (n >= 1 && n <= 39) nums.push(n);
    }
    if (nums.length === 5) {
      seenC.add(date);
      records.push({ date, numbers: nums.sort((a, b) => a - b) });
    }
    if (records.length >= 60) break;
  }

  return records;
}

/** 根據已知開獎號碼，自動比對並更新 prediction_logs 中的待確認 539 預測 */
async function autoCompare539Predictions(draws) {
  if (!draws.length) return;
  for (const d of draws) {
    const actualStr = d.numbers.map(n => String(n).padStart(2, '0')).join(' ');
    try {
      const [rows] = await pool.execute(
        `SELECT id, details FROM prediction_logs
         WHERE outcome = 'pending' AND type = 'lottery'
           AND JSON_UNQUOTE(JSON_EXTRACT(details, '$.drawNo')) REGEXP ?`,
        [d.date.replace('/', '\\/') + '$']
      );
      for (const row of rows) {
        const det = parse(row.details) || {};
        const predicted = (det.numbers || det.predictedNumbers || []).map(Number);
        const hits = predicted.filter(n => d.numbers.includes(n)).length;
        const score = hits / 5;
        const outcome = hits >= 3 ? 'correct' : hits >= 1 ? 'partial' : 'incorrect';
        await pool.execute(
          `UPDATE prediction_logs SET actual_result=?, outcome=?, accuracy_score=?, updated_at=NOW() WHERE id=?`,
          [actualStr, outcome, score, row.id]
        );
      }
      if (rows.length) console.log(`  🎯 539 對獎 [${d.date}]: ${actualStr} → 更新 ${rows.length} 筆`);
    } catch (e) { console.error(`  ❌ 539 對獎失敗 [${d.date}]:`, e.message); }
  }
}

/**
 * 從 pilio.idv.tw 抓取 539 開獎（支援多頁補全）
 * @param {object} opts
 * @param {number} opts.maxPages  最多抓幾頁（預設 1，全量補抓傳 10）
 */
async function fetch539AndCompare({ maxPages = 1 } = {}) {
  try {
    const allDraws = [];
    for (let page = 1; page <= maxPages; page++) {
      const url = `https://www.pilio.idv.tw/lto539/list.asp?indexpage=${page}&orderby=new`;
      const html = await fetchHtml(url);
      if (!html || html.length < 200) { console.warn(`⚠️ 539 第${page}頁回應異常，停止`); break; }
      const draws = parse539Html(html);
      if (!draws.length) { console.warn(`⚠️ 539 第${page}頁解析無結果，停止`); break; }
      allDraws.push(...draws);
      if (page < maxPages) await new Promise(r => setTimeout(r, 800)); // 禮貌性延遲
    }
    if (!allDraws.length) { console.error('⚠️ 539 所有頁面解析均無結果'); return; }

    // 去除重複日期（多頁可能有重疊）
    const seen = new Set();
    const unique = allDraws.filter(d => { if (seen.has(d.date)) return false; seen.add(d.date); return true; });

    for (const d of unique) {
      await pool.execute(
        `INSERT INTO lottery_draws_539 (draw_date, numbers) VALUES (?,?)
         ON DUPLICATE KEY UPDATE numbers=VALUES(numbers)`,
        [d.date, json(d.numbers)]
      ).catch(() => {});
    }
    console.log(`✅ 539 開獎更新: ${unique.length} 筆（頁數:${maxPages}，最新: ${unique[0]?.date}）`);
    await autoCompare539Predictions(unique);
  } catch (e) { console.error('539 fetch&compare 失敗:', e.message); }
}

/** 根據 DB 最新日期自動判斷需要抓幾頁（相差 >30天 就補全） */
async function smartFetch539() {
  try {
    const now = new Date();
    const [rows] = await pool.execute(
      'SELECT draw_date FROM lottery_draws_539 ORDER BY draw_date DESC LIMIT 1'
    );
    let maxPages = 1;
    if (rows.length) {
      const [mm, dd] = rows[0].draw_date.split('/').map(Number);
      let lastDate = new Date(now.getFullYear(), mm - 1, dd);
      if (lastDate > now) lastDate.setFullYear(now.getFullYear() - 1); // 跨年修正
      const daysBehind = Math.floor((now - lastDate) / 86400000);
      // 每頁約 30 筆，多 1 頁緩衝
      maxPages = Math.min(10, Math.max(1, Math.ceil(daysBehind / 25)));
      if (daysBehind > 5) console.log(`📅 539 DB 落後 ${daysBehind} 天，補抓 ${maxPages} 頁`);
    } else {
      maxPages = 10; // DB 空白，全量抓
    }
    await fetch539AndCompare({ maxPages });
  } catch (e) { console.error('smartFetch539 失敗:', e.message); }
}

// ════════════════════════════════════════════════════════════════
// 539 統計分析工具函式
// ════════════════════════════════════════════════════════════════

/** 從頭重建所有 539 分析表 */
async function rebuild539Analysis() {
  const [draws] = await pool.query(
    'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY id ASC'
  );
  if (draws.length === 0) { console.log('⚠️ lottery_draws_539 無資料'); return; }

  const parsed = draws.map(r => ({ drawDate: r.draw_date, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
  const total  = parsed.length;

  await pool.execute('DELETE FROM lottery_539_number_stats');
  await pool.execute('DELETE FROM lottery_539_transition');
  await pool.execute('DELETE FROM lottery_539_cooccurrence');
  const initVals = Array.from({ length: 39 }, (_, i) => [i + 1, 0, 0, 0, null, 0]);
  await pool.query(
    'INSERT INTO lottery_539_number_stats (number, times_drawn, current_miss, max_miss, last_drawn_date, total_draws) VALUES ?',
    [initVals]
  );

  // number_stats
  const nd = {};
  for (let n = 1; n <= 39; n++) nd[n] = { td: 0, cm: 0, mm: 0, ld: null, run: 0 };
  for (const { drawDate, numbers } of parsed) {
    const ns = new Set(numbers);
    for (let n = 1; n <= 39; n++) {
      const d = nd[n];
      if (ns.has(n)) { d.td++; if (d.run > d.mm) d.mm = d.run; d.run = 0; d.ld = drawDate; }
      else           { d.run++; }
    }
  }
  await Promise.all(Array.from({ length: 39 }, (_, i) => i + 1).map(n => {
    const d = nd[n]; const cm = d.run; if (cm > d.mm) d.mm = cm;
    return pool.execute(
      'UPDATE lottery_539_number_stats SET times_drawn=?,current_miss=?,max_miss=?,last_drawn_date=?,total_draws=? WHERE number=?',
      [d.td, cm, d.mm, d.ld, total, n]
    );
  }));

  // transition_matrix
  const transMap = {};
  for (let i = 1; i < parsed.length; i++) {
    for (const f of parsed[i - 1].numbers) {
      if (!transMap[f]) transMap[f] = {};
      for (const t of parsed[i].numbers)
        transMap[f][t] = (transMap[f][t] || 0) + 1;
    }
  }
  const transRows = [];
  for (const [f, toMap] of Object.entries(transMap)) {
    const tot = Object.values(toMap).reduce((s, c) => s + c, 0);
    for (const [t, c] of Object.entries(toMap))
      transRows.push([+f, +t, c, c / tot]);
  }
  if (transRows.length > 0)
    await pool.query('INSERT INTO lottery_539_transition (from_num,to_num,count,probability) VALUES ?', [transRows]);

  // co-occurrence
  const coMap = {};
  for (const { numbers } of parsed) {
    const s = [...numbers].sort((a, b) => a - b);
    for (let a = 0; a < s.length; a++)
      for (let b = a + 1; b < s.length; b++) {
        const k = s[a] * 100 + s[b];
        coMap[k] = (coMap[k] || 0) + 1;
      }
  }
  const coRows = Object.entries(coMap).map(([k, c]) => [Math.floor(+k / 100), +k % 100, c]);
  if (coRows.length > 0)
    await pool.query('INSERT INTO lottery_539_cooccurrence (num_a,num_b,count) VALUES ?', [coRows]);

  console.log(`✅ 539 analysis rebuilt: ${total} 期, ${transRows.length} 轉移, ${coRows.length} 共現`);
}

/** 儲存 539 預測（在開獎前觸發，drawDate 為今日） */
async function save539Prediction(drawDate) {
  try {
    const [exists] = await pool.query(
      'SELECT draw_date FROM lottery_539_prediction_results WHERE draw_date=?', [drawDate]
    );
    if (exists.length > 0) return;

    const [rows] = await pool.query(
      'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY id DESC LIMIT 80'
    );
    if (rows.length === 0) return;

    const records = rows.map(r => ({ drawDate: r.draw_date, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
    const { buildLotteryStats, scoreNumbers } = require('./routes/lottery_predict');
    const work = records.slice(0, 50);
    const { stats, freq, N } = buildLotteryStats(work);
    const sc   = scoreNumbers(work, stats, freq, N);
    const recommended = sc.map((v, i) => [i, v]).slice(1)
      .sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n]) => n).sort((a, b) => a - b);

    await pool.execute(
      'INSERT IGNORE INTO lottery_539_prediction_results (draw_date, predicted_numbers) VALUES (?,?)',
      [drawDate, JSON.stringify(recommended)]
    );
    console.log(`🔮 539 預測已儲存 [${drawDate}]: [${recommended.join(',')}]`);
  } catch (e) { console.error('save539Prediction:', e.message); }
}

/** 增量更新 539 分析表（每次新開獎後呼叫） */
async function update539Analysis(drawDate, newNums) {
  const numSet = new Set(newNums);

  // number_stats
  const drawn  = newNums;
  const missed = Array.from({ length: 39 }, (_, i) => i + 1).filter(n => !numSet.has(n));
  if (drawn.length > 0) {
    await pool.execute(
      `UPDATE lottery_539_number_stats
       SET times_drawn=times_drawn+1, max_miss=GREATEST(max_miss,current_miss),
           current_miss=0, last_drawn_date=?, total_draws=total_draws+1
       WHERE number IN (${drawn.map(() => '?').join(',')})`,
      [drawDate, ...drawn]
    );
  }
  if (missed.length > 0) {
    await pool.execute(
      `UPDATE lottery_539_number_stats
       SET current_miss=current_miss+1, max_miss=GREATEST(max_miss,current_miss+1),
           total_draws=total_draws+1
       WHERE number IN (${missed.map(() => '?').join(',')})`,
      missed
    );
  }

  // transition（前一期 → 當期）
  const [prevRow] = await pool.query(
    'SELECT numbers FROM lottery_draws_539 ORDER BY id DESC LIMIT 1,1'
  );
  if (prevRow.length > 0) {
    const prevNums = Array.isArray(prevRow[0].numbers)?prevRow[0].numbers:JSON.parse(prevRow[0].numbers);
    const pairs    = [];
    for (const f of prevNums) for (const t of newNums) pairs.push([f, t]);
    if (pairs.length > 0) {
      await pool.execute(
        `INSERT INTO lottery_539_transition (from_num,to_num,count) VALUES ${pairs.map(() => '(?,?,1)').join(',')}
         ON DUPLICATE KEY UPDATE count=count+1`,
        pairs.flat()
      );
      for (const f of new Set(prevNums)) {
        const [[row]] = await pool.query(
          'SELECT SUM(count) as total FROM lottery_539_transition WHERE from_num=?', [f]
        );
        if (row.total) await pool.execute(
          'UPDATE lottery_539_transition SET probability=count/? WHERE from_num=?', [row.total, f]
        );
      }
    }
  }

  // co-occurrence
  const s = [...newNums].sort((a, b) => a - b);
  const coPairs = [];
  for (let a = 0; a < s.length; a++)
    for (let b = a + 1; b < s.length; b++) coPairs.push([s[a], s[b]]);
  if (coPairs.length > 0) {
    await pool.execute(
      `INSERT INTO lottery_539_cooccurrence (num_a,num_b,count) VALUES ${coPairs.map(() => '(?,?,1)').join(',')}
       ON DUPLICATE KEY UPDATE count=count+1`,
      coPairs.flat()
    );
  }
}

// 每天 20:30（週一至週六）存預測
cron.schedule('30 20 * * 1-6', async () => {
  const now   = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Taipei' }));
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day   = String(now.getDate()).padStart(2, '0');
  await save539Prediction(`${month}/${day}`);
}, { timezone: 'Asia/Taipei' });

// 每天 20:35（週一至週六）自動抓取 539 開獎並對獎（539 週一~週六 20:30 開獎）
cron.schedule('35 20 * * 1-6', async () => {
  console.log('⏰ 539 定時開獎抓取...');
  await fetch539AndCompare({ maxPages: 1 });

  // 找出今日開獎，更新 539 分析表 + 預測對照
  const now   = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Taipei' }));
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day   = String(now.getDate()).padStart(2, '0');
  const today = `${month}/${day}`;

  const [rows] = await pool.query(
    'SELECT numbers FROM lottery_draws_539 WHERE draw_date=? LIMIT 1', [today]
  );
  if (rows.length > 0) {
    const nums = JSON.parse(rows[0].numbers);
    await update539Analysis(today, nums);

    const [pred] = await pool.query(
      'SELECT predicted_numbers FROM lottery_539_prediction_results WHERE draw_date=?', [today]
    );
    if (pred.length > 0) {
      const predicted = Array.isArray(pred[0].predicted_numbers)?pred[0].predicted_numbers:JSON.parse(pred[0].predicted_numbers);
      const hitCount  = nums.filter(n => predicted.includes(n)).length;
      await pool.execute(
        'UPDATE lottery_539_prediction_results SET actual_numbers=?, hit_count=? WHERE draw_date=?',
        [JSON.stringify(nums), hitCount, today]
      );
      console.log(`🎯 539 對獎 [${today}]: 命中 ${hitCount}/5`);
    }
  }
}, { timezone: 'Asia/Taipei' });

// 每天 09:00 也補抓昨日結果（防止前晚失敗）
cron.schedule('0 9 * * *', async () => {
  await smartFetch539();
}, { timezone: 'Asia/Taipei' });

// 手動觸發：POST /api/analysis/rebuild — 重建所有分析表
app.post('/api/analysis/rebuild', async (req, res) => {
  const type = req.body?.type || 'all'; // 'bingo' | '539' | 'all'
  try {
    if (type === 'bingo' || type === 'all') await rebuildBingoAnalysis();
    if (type === '539'  || type === 'all') await rebuild539Analysis();
    res.json({ ok: true, rebuilt: type });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 手動觸發：POST /api/lottery/539/sync-now
// body: { fullSync: true } 可強制補全多頁
app.post('/api/lottery/539/sync-now', async (req, res) => {
  try {
    const fullSync = req.body?.fullSync === true;
    if (fullSync) {
      await smartFetch539();
    } else {
      await fetch539AndCompare({ maxPages: 1 });
    }
    const [rows] = await pool.execute(
      'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY draw_date DESC LIMIT 10'
    );
    res.json({ ok: true, synced: fullSync, latest: rows.map(r => ({ date: r.draw_date, numbers: parse(r.numbers) })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════
// 539 預測記錄儲存
// ════════════════════════════════════════════════════════════════

app.post('/api/lottery/539/prediction-save', async (req, res) => {
  const { drawDate, numbers, reasons, mathStats, newspaper } = req.body;
  if (!drawDate || !Array.isArray(numbers) || numbers.length !== 5) {
    return res.status(400).json({ error: '參數錯誤' });
  }
  try {
    const [result] = await pool.execute(
      `INSERT INTO lottery_539_predictions (draw_date, numbers, reasons, math_stats, newspaper)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE numbers=VALUES(numbers), reasons=VALUES(reasons),
                               math_stats=VALUES(math_stats), newspaper=VALUES(newspaper)`,
      [drawDate, JSON.stringify(numbers), JSON.stringify(reasons ?? {}),
       JSON.stringify(mathStats ?? {}), JSON.stringify(newspaper ?? {})]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/lottery/539/predictions', async (req, res) => {
  const { limit = 30 } = req.query;
  try {
    const [rows] = await pool.execute(
      `SELECT id, draw_date, numbers, reasons, math_stats, newspaper, created_at
       FROM lottery_539_predictions ORDER BY draw_date DESC LIMIT ${parseInt(limit)}` );
    res.json(rows.map(r => ({
      ...r,
      numbers:    parse(r.numbers),
      reasons:    parse(r.reasons),
      math_stats: parse(r.math_stats),
      newspaper:  parse(r.newspaper),
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 體育預測邏輯記錄儲存
// ════════════════════════════════════════════════════════════════

app.post('/api/sports/prediction-save', async (req, res) => {
  const { matchDate, homeTeam, awayTeam, sport, predictionData } = req.body;
  if (!matchDate || !homeTeam || !awayTeam) {
    return res.status(400).json({ error: '參數錯誤' });
  }
  try {
    const [result] = await pool.execute(
      `INSERT INTO sports_predictions (match_date, sport, home_team, away_team, prediction_data)
       VALUES (?, ?, ?, ?, ?)`,
      [matchDate, sport ?? 'MLB', homeTeam, awayTeam, JSON.stringify(predictionData ?? {})]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/sports/predictions', async (req, res) => {
  const { limit = 20, sport } = req.query;
  try {
    const [rows] = await pool.execute(
      `SELECT id, match_date, sport, home_team, away_team, prediction_data, created_at
       FROM sports_predictions
       ${sport ? 'WHERE sport = ' + pool.escape(sport) : ''}
       ORDER BY match_date DESC, id DESC LIMIT ${parseInt(limit)}`);
    res.json(rows.map(r => ({ ...r, prediction_data: parse(r.prediction_data) })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// Whitebear 私人金庫（AES-256-GCM 加密，僅密碼持有人可讀）
// ════════════════════════════════════════════════════════════════

const WB_SALT = 'whitebear-pangpang-salt-v1';
const WB_ITER = 200000;

function wbDeriveKey(password) {
  return crypto.pbkdf2Sync(password, WB_SALT, WB_ITER, 32, 'sha256');
}

function wbEncrypt(password, plaintext) {
  const key  = wbDeriveKey(password);
  const iv   = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc  = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag  = cipher.getAuthTag();
  return iv.toString('hex') + ':' + tag.toString('hex') + ':' + enc.toString('hex');
}

function wbDecrypt(password, ciphertext) {
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  const key    = wbDeriveKey(password);
  const iv     = Buffer.from(ivHex,  'hex');
  const tag    = Buffer.from(tagHex, 'hex');
  const enc    = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc) + decipher.final('utf8');
}

// 寫入金庫（需密碼）
app.post('/api/whitebear/save', async (req, res) => {
  const { password, category, title, content } = req.body;
  if (!password || !title || !content) return res.status(400).json({ error: '參數不完整' });
  try {
    const conn = await pool.getConnection();
    const enc = wbEncrypt(password, content);
    const [result] = await conn.execute(
      `INSERT INTO whitebear_vault (category, title, content_enc) VALUES (?, ?, ?)`,
      [category ?? 'general', title, enc]
    );
    conn.release();
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 讀取金庫（需密碼；密碼錯誤則 GCM 驗證失敗）
app.post('/api/whitebear/read', async (req, res) => {
  const { password, category, id } = req.body;
  if (!password) return res.status(400).json({ error: '需要密碼' });
  try {
    const conn = await pool.getConnection();
    // table exists (created by schema.sql)
    let query = 'SELECT id, category, title, content_enc, created_at, updated_at FROM whitebear_vault';
    const params = [];
    const conds = [];
    if (id)       { conds.push('id = ?');       params.push(id); }
    if (category) { conds.push('category = ?'); params.push(category); }
    if (conds.length) query += ' WHERE ' + conds.join(' AND ');
    query += ' ORDER BY id DESC';
    const [rows] = await conn.execute(query, params);
    conn.release();
    const decrypted = [];
    for (const row of rows) {
      try {
        const plain = wbDecrypt(password, row.content_enc);
        decrypted.push({ id: row.id, category: row.category, title: row.title,
                         content: plain, createdAt: row.created_at, updatedAt: row.updated_at });
      } catch {
        return res.status(403).json({ error: '密碼錯誤或資料損毀' });
      }
    }
    res.json(decrypted);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 刪除金庫項目（需密碼驗證）
app.post('/api/whitebear/delete', async (req, res) => {
  const { password, id } = req.body;
  if (!password || !id) return res.status(400).json({ error: '參數不完整' });
  try {
    const conn = await pool.getConnection();
    // table exists (created by schema.sql)
    // 先確認密碼正確（嘗試解密）
    const [rows] = await conn.execute(
      'SELECT content_enc FROM whitebear_vault WHERE id = ?', [id]);
    if (!rows.length) { conn.release(); return res.status(404).json({ error: '找不到此項目' }); }
    try { wbDecrypt(password, rows[0].content_enc); } catch {
      conn.release(); return res.status(403).json({ error: '密碼錯誤' });
    }
    await conn.execute('DELETE FROM whitebear_vault WHERE id = ?', [id]);
    conn.release();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// API Keys 管理
// ════════════════════════════════════════════════════════════════

app.get('/api/config/keys', requireAdminKey, async (req, res) => {
  res.json({
    oddsApiKey:    process.env.ODDS_API_KEY    || '',
    openAiApiKey:  process.env.OPENAI_API_KEY  || '',
    rapidApiKey:   process.env.RAPIDAPI_KEY    || '',
  });
});

app.get('/api/config/public', async (req, res) => {
  res.json({
    espnBaseUrl: 'https://site.api.espn.com/v2/site/en/sports',
    backendUrl:  process.env.BACKEND_URL || '',
    testMode:    process.env.ECPAY_TEST_MODE === 'true',
  });
});

// ── 每日清除過期預測（prediction_logs 和 prediction_analysis_detail 保留 8 天）──
async function cleanupExpiredPredictions() {
  try {
    await pool.execute('DELETE FROM prediction_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 8 DAY)');
    await pool.execute('DELETE FROM prediction_analysis_detail WHERE expires_at < NOW()');
    await pool.execute('DELETE FROM chart_cache WHERE expires_at < NOW()');
    console.log('✅ 過期預測清除完成');
  } catch (e) {
    console.error('清除過期預測失敗:', e.message);
  }
}
setInterval(cleanupExpiredPredictions, 24 * 60 * 60 * 1000); // 每24小時
cleanupExpiredPredictions(); // 啟動時執行一次

// 啟動時智能補抓 539（30 秒後，根據 DB 落後天數自動決定頁數）
setTimeout(() => smartFetch539().catch(() => {}), 30 * 1000);

// 啟動時重建分析表（60 秒後，不影響主流程啟動）
setTimeout(async () => {
  console.log('🔄 啟動分析資料重建...');
  try { await rebuild539Analysis(); } catch (e) { console.error('539 rebuild failed:', e.message); }
  try { await rebuildBingoAnalysis(); } catch (e) { console.error('bingo rebuild failed:', e.message); }
}, 60 * 1000);

// ── 啟動（TLS 優先，找不到憑證則降回 HTTP）────────────────────
const PORT      = parseInt(process.env.PORT  || '3000');
const HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '3443');

function startInfo(proto, port) {
  console.log(`🚀 胖胖體育 API 啟動 ${proto} Port: ${port}`);
  console.log(`   DB: ${process.env.MYSQL_DATABASE || 'my_database'} @ ${process.env.MYSQL_HOST || 'localhost'}`);
  console.log(`   ECPay: ${process.env.ECPAY_TEST_MODE === 'true' ? '測試模式' : '正式模式'}`);
  console.log(`   CORS: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : '開放（開發模式）'}`);
  console.log(`   定時任務: 賓果每5分鐘 / 彩券每天21:20 / 快取每天03:00`);
}

const SSL_KEY  = process.env.SSL_KEY_PATH;
const SSL_CERT = process.env.SSL_CERT_PATH;

if (SSL_KEY && SSL_CERT && fs.existsSync(SSL_KEY) && fs.existsSync(SSL_CERT)) {
  // HTTPS 模式（憑證路徑由 .env SSL_KEY_PATH / SSL_CERT_PATH 指定）
  const tlsOptions = {
    key:  fs.readFileSync(SSL_KEY),
    cert: fs.readFileSync(SSL_CERT),
  };
  https.createServer(tlsOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => startInfo('HTTPS', HTTPS_PORT));
  // HTTP → 自動導向 HTTPS
  http.createServer((req, res) => {
    res.writeHead(301, { Location: `https://${req.headers.host.replace(/:\d+$/, '')}:${HTTPS_PORT}${req.url}` });
    res.end();
  }).listen(PORT, '0.0.0.0', () => console.log(`   HTTP :${PORT} → 自動導向 HTTPS :${HTTPS_PORT}`));
} else {
  // HTTP 模式（開發 / 反向代理後端）
  http.createServer(app).listen(PORT, '0.0.0.0', () => startInfo('HTTP', PORT));
  if (SSL_KEY || SSL_CERT) console.warn('⚠️  SSL_KEY_PATH / SSL_CERT_PATH 設定了但找不到檔案，以 HTTP 啟動');
}
