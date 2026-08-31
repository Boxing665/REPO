'use strict';
// ── 賓果 + 539 統計分析 API ─────────────────────────────────────────────────
const express = require('express');
const router  = express.Router();

const { buildStats, computePredictScores } = require('./bingo_analyze');
const { buildLotteryStats, scoreNumbers }   = require('./lottery_predict');

// ── 共用工具 ──────────────────────────────────────────────────────────────────

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

// ── 回測引擎 ──────────────────────────────────────────────────────────────────

/**
 * 賓果回測：用前 N 期資料預測，驗證下一期命中顆數
 * @param {Array} draws   [{drawNo, numbers}] 最新在前
 * @param {number} testN  要測試幾期
 * @returns {{ avgHits, hitRates, sampleSize, recent }}
 */
function backtestBingo(draws, testN = 300) {
  const test = draws.slice(0, Math.min(testN, draws.length - 20));
  const results = [];

  for (let i = 0; i < test.length - 10; i++) {
    const training = draws.slice(i + 1, i + 1 + 60);
    if (training.length < 10) continue;

    const { stats, rawFreq, N } = buildStats(training);
    const sc = computePredictScores(training, stats, rawFreq, N, 'balanced', {}, [], [], []);
    const predicted = new Set(
      sc.map((v, idx) => [idx, v]).slice(1)
        .sort((a, b) => b[1] - a[1]).slice(0, 20).map(([n]) => n)
    );

    const actual = test[i].numbers;
    const hits   = actual.filter(n => predicted.has(n)).length;
    results.push({ drawNo: test[i].drawNo, hits });
  }

  if (results.length === 0) return { avgHits: 0, hitRates: [], sampleSize: 0, recent: [] };

  const avgHits = results.reduce((s, r) => s + r.hits, 0) / results.length;
  const hitRates = [0,2,4,6,8,10,12,15].map(t => ({
    target: t,
    rate: +(results.filter(r => r.hits >= t).length / results.length * 100).toFixed(1),
  }));

  return { avgHits: +avgHits.toFixed(2), hitRates, sampleSize: results.length, recent: results.slice(0, 30) };
}

/**
 * 539 回測：每次用前 N 期預測 5 顆，算命中數
 */
function backtest539(draws, testN = 200) {
  const test = draws.slice(0, Math.min(testN, draws.length - 10));
  const results = [];

  for (let i = 0; i < test.length - 5; i++) {
    const training = draws.slice(i + 1, i + 1 + 50);
    if (training.length < 5) continue;

    const { stats, freq, N } = buildLotteryStats(training);
    const sc = scoreNumbers(training, stats, freq, N);
    const predicted = new Set(
      sc.map((v, idx) => [idx, v]).slice(1)
        .sort((a, b) => b[1] - a[1]).slice(0, 5).map(([n]) => n)
    );

    const actual = test[i].numbers;
    const hits   = actual.filter(n => predicted.has(n)).length;
    results.push({ drawDate: test[i].drawDate, hits });
  }

  if (results.length === 0) return { avgHits: 0, hitRates: [], sampleSize: 0, recent: [] };

  const avgHits = results.reduce((s, r) => s + r.hits, 0) / results.length;
  const hitRates = [0,1,2,3,4,5].map(t => ({
    target: t,
    rate: +(results.filter(r => r.hits >= t).length / results.length * 100).toFixed(1),
  }));

  return { avgHits: +avgHits.toFixed(2), hitRates, sampleSize: results.length, recent: results.slice(0, 30) };
}

// ════════════════════════════════════════════════════════════════
// 賓果分析 API
// ════════════════════════════════════════════════════════════════

/** GET /api/analysis/bingo/stats — 各號碼熱冷遺漏統計 */
router.get('/bingo/stats', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    const [rows] = await pool.query(
      'SELECT number, times_drawn, current_miss, max_miss, last_drawn_no, total_draws FROM bingo_number_stats ORDER BY number ASC'
    );
    if (rows.length === 0) return res.json({ stats: [], message: '尚無統計資料，請先跑 rebuild' });

    const total = rows[0].total_draws || 1;
    const stats = rows.map(r => ({
      ...r,
      avgGap: r.times_drawn > 0 ? +(total / r.times_drawn).toFixed(1) : total,
      hotScore: r.times_drawn > 0 ? +(r.times_drawn / total * 100).toFixed(2) : 0,
      isMissing: r.current_miss > (total / Math.max(r.times_drawn, 1)) * 1.5,
    }));

    const hotNumbers  = [...stats].sort((a, b) => b.times_drawn - a.times_drawn).slice(0, 20).map(s => s.number);
    const coldNumbers = [...stats].sort((a, b) => a.times_drawn - b.times_drawn).slice(0, 20).map(s => s.number);
    const missing     = [...stats].filter(s => s.isMissing).sort((a, b) => b.current_miss - a.current_miss).slice(0, 20).map(s => s.number);

    res.json({ stats, hotNumbers, coldNumbers, missing, totalDraws: total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/bingo/transition?from=5&limit=20 — 某號碼後最可能跟出的號碼 */
router.get('/bingo/transition', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const from  = parseInt(req.query.from);
    const limit = parseInt(req.query.limit) || 20;

    if (from >= 1 && from <= 80) {
      const [rows] = await pool.query(
        'SELECT to_num, count, probability FROM bingo_transition_matrix WHERE from_num=? ORDER BY probability DESC LIMIT ?',
        [from, limit]
      );
      return res.json({ from, transitions: rows });
    }

    // 全矩陣 top pairs
    const [rows] = await pool.query(
      'SELECT from_num, to_num, count, probability FROM bingo_transition_matrix ORDER BY probability DESC LIMIT ?',
      [limit]
    );
    res.json({ transitions: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/bingo/cooccurrence?num=5&limit=20 — 某號碼最常同期出現的號碼 */
router.get('/bingo/cooccurrence', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const num   = parseInt(req.query.num);
    const limit = parseInt(req.query.limit) || 20;

    if (num >= 1 && num <= 80) {
      const [rows] = await pool.query(
        `SELECT CASE WHEN num_a=? THEN num_b ELSE num_a END as partner, count
         FROM bingo_cooccurrence WHERE num_a=? OR num_b=?
         ORDER BY count DESC LIMIT ?`,
        [num, num, num, limit]
      );
      return res.json({ num, partners: rows });
    }

    // 全局 top co-occurring pairs
    const [rows] = await pool.query(
      'SELECT num_a, num_b, count FROM bingo_cooccurrence ORDER BY count DESC LIMIT ?',
      [limit]
    );
    res.json({ pairs: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/bingo/backtest?limit=300 — 預測回測 */
router.get('/bingo/backtest', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const limit = Math.min(parseInt(req.query.limit) || 300, 1000);
    const [rows] = await pool.query(
      'SELECT draw_no, numbers FROM bingo_draws ORDER BY draw_no DESC LIMIT ?', [limit + 20]
    );
    if (rows.length < 20) return res.json({ error: '資料不足，需至少 20 期' });

    const draws = rows.map(r => ({ drawNo: r.draw_no, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
    const result = backtestBingo(draws, limit);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/bingo/prediction-accuracy — 近期預測 vs 實際 */
router.get('/bingo/prediction-accuracy', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    const limit = parseInt(req.query.limit) || 100;
    const [rows] = await pool.query(
      `SELECT draw_no, predicted_numbers, actual_numbers, hit_count, created_at, updated_at
       FROM bingo_prediction_results ORDER BY draw_no DESC LIMIT ?`, [limit]
    );
    const judged = rows.filter(r => r.actual_numbers !== null);
    const avgHit = judged.length > 0
      ? (judged.reduce((s, r) => s + (r.hit_count || 0), 0) / judged.length).toFixed(2)
      : 0;
    const dist = [0,1,2,3,4,5,6,7,8,9,10].map(h => ({
      hits: h,
      count: judged.filter(r => r.hit_count === h).length,
    }));
    res.json({ records: rows, judgedCount: judged.length, avgHitCount: +avgHit, hitDistribution: dist });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════════════════════════════
// 539 分析 API
// ════════════════════════════════════════════════════════════════

/** GET /api/analysis/539/stats */
router.get('/539/stats', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    const [rows] = await pool.query(
      'SELECT number, times_drawn, current_miss, max_miss, last_drawn_date, total_draws FROM lottery_539_number_stats ORDER BY number ASC'
    );
    if (rows.length === 0) return res.json({ stats: [], message: '尚無統計資料' });

    const total = rows[0].total_draws || 1;
    const stats = rows.map(r => ({
      ...r,
      avgGap: r.times_drawn > 0 ? +(total / r.times_drawn).toFixed(1) : total,
      isMissing: r.current_miss > (total / Math.max(r.times_drawn, 1)) * 1.5,
    }));

    const hotNumbers  = [...stats].sort((a, b) => b.times_drawn - a.times_drawn).slice(0, 10).map(s => s.number);
    const coldNumbers = [...stats].sort((a, b) => a.times_drawn - b.times_drawn).slice(0, 10).map(s => s.number);
    const missing     = [...stats].filter(s => s.isMissing).sort((a, b) => b.current_miss - a.current_miss).map(s => s.number);

    res.json({ stats, hotNumbers, coldNumbers, missing, totalDraws: total });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/539/transition?from=5&limit=15 */
router.get('/539/transition', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const from  = parseInt(req.query.from);
    const limit = parseInt(req.query.limit) || 15;

    if (from >= 1 && from <= 39) {
      const [rows] = await pool.query(
        'SELECT to_num, count, probability FROM lottery_539_transition WHERE from_num=? ORDER BY probability DESC LIMIT ?',
        [from, limit]
      );
      return res.json({ from, transitions: rows });
    }

    const [rows] = await pool.query(
      'SELECT from_num, to_num, count, probability FROM lottery_539_transition ORDER BY probability DESC LIMIT ?',
      [limit]
    );
    res.json({ transitions: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/539/cooccurrence?num=5&limit=15 */
router.get('/539/cooccurrence', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const num   = parseInt(req.query.num);
    const limit = parseInt(req.query.limit) || 15;

    if (num >= 1 && num <= 39) {
      const [rows] = await pool.query(
        `SELECT CASE WHEN num_a=? THEN num_b ELSE num_a END as partner, count
         FROM lottery_539_cooccurrence WHERE num_a=? OR num_b=?
         ORDER BY count DESC LIMIT ?`,
        [num, num, num, limit]
      );
      return res.json({ num, partners: rows });
    }

    const [rows] = await pool.query(
      'SELECT num_a, num_b, count FROM lottery_539_cooccurrence ORDER BY count DESC LIMIT ?',
      [limit]
    );
    res.json({ pairs: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/539/backtest?limit=200 */
router.get('/539/backtest', async (req, res) => {
  try {
    const pool  = req.app.get('pool');
    const limit = Math.min(parseInt(req.query.limit) || 200, 500);
    const [rows] = await pool.query(
      'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY id DESC LIMIT ?', [limit + 10]
    );
    if (rows.length < 10) return res.json({ error: '資料不足' });

    const draws = rows.map(r => ({ drawDate: r.draw_date, numbers: Array.isArray(r.numbers)?r.numbers:JSON.parse(r.numbers) }));
    const result = backtest539(draws, limit);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /api/analysis/539/prediction-accuracy */
router.get('/539/prediction-accuracy', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    const limit = parseInt(req.query.limit) || 100;
    const [rows] = await pool.query(
      `SELECT draw_date, predicted_numbers, actual_numbers, hit_count, created_at
       FROM lottery_539_prediction_results ORDER BY draw_date DESC LIMIT ?`, [limit]
    );
    const judged = rows.filter(r => r.actual_numbers !== null);
    const avgHit = judged.length > 0
      ? (judged.reduce((s, r) => s + (r.hit_count || 0), 0) / judged.length).toFixed(2)
      : 0;
    const dist = [0,1,2,3,4,5].map(h => ({
      hits: h,
      count: judged.filter(r => r.hit_count === h).length,
    }));
    res.json({ records: rows, judgedCount: judged.length, avgHitCount: +avgHit, hitDistribution: dist });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
