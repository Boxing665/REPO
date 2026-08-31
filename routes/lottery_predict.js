'use strict';
// ── 539 預測引擎（後端版）─────────────────────────────────────────────────
const express = require('express');
const router  = express.Router();

function expDecay(i, rate = 0.12) { return Math.exp(-rate * i); }

function buildLotteryStats(records) {
  const N = records.length;
  const freq   = new Array(40).fill(0);
  const lastAt = new Array(40).fill(null);
  const expW   = new Array(40).fill(0);

  for (let i = 0; i < N; i++) {
    const w = expDecay(i);
    for (const n of records[i].numbers) {
      if (n < 1 || n > 39) continue;
      freq[n]++;
      if (lastAt[n] === null) lastAt[n] = i;
      expW[n] += w;
    }
  }

  const maxW = Math.max(...expW.slice(1), 0.1);
  const stats = {};
  for (let n = 1; n <= 39; n++) {
    const f   = freq[n];
    const gap = lastAt[n] !== null ? lastAt[n] : N;
    const avg = f > 0 ? N / f : N;
    const heat = Math.min(1, (expW[n] / maxW) * 0.6 + 0.4 / (gap + 1));
    stats[n] = { number: n, frequency: f, gap, avgGap: avg, heatScore: heat };
  }
  return { stats, freq, N };
}

function scoreNumbers(records, stats, freq, N) {
  const scores = new Array(40).fill(0);

  // 1. 拖牌轉移機率 (Lag 1–5)
  const maxLag = Math.min(5, N - 1);
  for (let lag = 1; lag <= maxLag; lag++) {
    const fromToCount = {}, fromTotal = {};
    for (let i = 0; i + lag < N; i++) {
      const toSet = new Set(records[i].numbers);
      for (const f of records[i + lag].numbers) {
        if (f < 1 || f > 39) continue;
        fromTotal[f] = (fromTotal[f] || 0) + 1;
        if (!fromToCount[f]) fromToCount[f] = {};
        for (const t of toSet) fromToCount[f][t] = (fromToCount[f][t] || 0) + 1;
      }
    }
    if (lag > records.length) continue;
    const w = 1 / lag;
    for (const f of records[lag - 1].numbers) {
      const tot = fromTotal[f] || 0;
      if (tot < 3) continue;
      for (const [t, cnt] of Object.entries(fromToCount[f] || {})) {
        const rate = cnt / tot;
        if (rate >= 0.12) scores[+t] += rate * w * 15;
      }
    }
  }

  // 2. 間隔到期
  for (let n = 1; n <= 39; n++) {
    const s = stats[n];
    if (s.gap >= s.avgGap) scores[n] += Math.min(s.gap - s.avgGap, 15) * 1.8;
  }

  // 3. 熱度
  for (let n = 1; n <= 39; n++) scores[n] += stats[n].heatScore * 10;

  // 4. 近5期連開強化
  const streak5 = new Array(40).fill(0);
  for (const r of records.slice(0, 5)) for (const n of r.numbers) if (n >= 1 && n <= 39) streak5[n]++;
  for (let n = 1; n <= 39; n++) {
    if (streak5[n] >= 3) scores[n] += streak5[n] * 8;
    else if (streak5[n] === 2) scores[n] += 4;
  }

  // 5. Jaccard 共現
  const coLimit = Math.min(25, N);
  const co = {};
  for (let i = 0; i < coLimit; i++) {
    const nums = records[i].numbers.filter(n => n >= 1 && n <= 39);
    for (let j = 0; j < nums.length; j++)
      for (let k = j + 1; k < nums.length; k++) {
        const [a, b] = [nums[j], nums[k]];
        if (!co[a]) co[a] = {};
        if (!co[b]) co[b] = {};
        co[a][b] = (co[a][b] || 0) + 1;
        co[b][a] = (co[b][a] || 0) + 1;
      }
  }
  const seedTop = scores.map((v, i) => [i, v]).slice(1)
    .sort((a, b) => b[1] - a[1]).slice(0, 10).map(([n]) => n);
  const seeds = new Set(seedTop);
  for (let n = 1; n <= 39; n++) {
    let aff = 0, cnt = 0;
    for (const s of seeds) {
      const c = (co[s] && co[s][n]) || 0;
      if (c > 0) { aff += c / Math.sqrt(Math.max(freq[n], 1) * Math.max(freq[s], 1)); cnt++; }
    }
    if (cnt > 0) scores[n] += (aff / seeds.size) * 14;
  }

  return scores;
}

/**
 * POST /api/lottery/539/predict
 * Body: { records?: [{drawNo, numbers}], count?: 5 }
 */
router.post('/predict', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    let records = req.body.records;
    const count = req.body.count || 5;

    if (!records || records.length === 0) {
      const [rows] = await pool.query(
        'SELECT draw_date, numbers FROM lottery_draws_539 ORDER BY id DESC LIMIT 80'
      );
      records = rows.map(r => ({
        drawDate: r.draw_date,
        numbers:  Array.isArray(r.numbers) ? r.numbers : JSON.parse(r.numbers),
      }));
    }

    if (records.length === 0) return res.json({ recommended: [], scores: {} });

    const work = records.slice(0, 50);
    const { stats, freq, N } = buildLotteryStats(work);

    const scoreArr = scoreNumbers(work, stats, freq, N);
    const baseScores = {};
    for (let n = 1; n <= 39; n++) baseScores[n] = scoreArr[n];

    const sorted = scoreArr.map((v, i) => [i, v]).slice(1).sort((a, b) => b[1] - a[1]);
    const recommended = sorted.slice(0, count).map(([n]) => n).sort((a, b) => a - b);

    const nextDrawDate = records[0]?.drawDate || '';

    // 儲存本次預測到 DB（用 IGNORE 避免重複）
    if (nextDrawDate) {
      pool.execute(
        'INSERT IGNORE INTO lottery_539_prediction_results (draw_date, predicted_numbers) VALUES (?,?)',
        [nextDrawDate + '_next', JSON.stringify(recommended)]
      ).catch(() => {});
    }

    res.json({
      recommended,
      nextDrawDate,
      analyzedDraws: N,
      baseScores,
      stats: Object.fromEntries(Object.entries(stats).map(([k, v]) => [k, {
        number: v.number, frequency: v.frequency, gap: v.gap,
        avgGap: v.avgGap, heatScore: v.heatScore,
      }])),
    });
  } catch (e) {
    console.error('[lottery/539/predict]', e);
    res.status(500).json({ error: e.message });
  }
});

// ── 匯出核心函式供 server.js cron 和 analysis.js 使用 ────────────────────────
router.buildLotteryStats = buildLotteryStats;
router.scoreNumbers      = scoreNumbers;
module.exports = router;
