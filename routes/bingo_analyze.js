'use strict';
// ── 賓果賓果分析引擎（從 Flutter BingoService.analyze() 移植）──────────────
const express = require('express');
const router  = express.Router();

// ── 純計算工具 ────────────────────────────────────────────────────────────

function expDecay(i, rate = 0.06) { return Math.exp(-rate * i); }

/** 建立每個號碼的基本統計 */
function buildStats(records) {
  const N = records.length;
  const rawFreq   = new Array(81).fill(0);
  const lastSeen  = new Array(81).fill(null);
  const expW      = new Array(81).fill(0);

  for (let i = 0; i < N; i++) {
    const w = expDecay(i);
    for (const n of records[i].numbers) {
      rawFreq[n]++;
      if (lastSeen[n] === null) lastSeen[n] = i;
      expW[n] += w;
    }
  }

  const maxW = Math.max(...expW.slice(1), 0.1);
  const stats = {};

  for (let n = 1; n <= 80; n++) {
    const freq   = rawFreq[n];
    const gap    = lastSeen[n] !== null ? lastSeen[n] : N;
    const avgGap = freq > 0 ? N / freq : N;
    const heat   = Math.min(1, (expW[n] / maxW) * 0.6 + 0.4 / (gap + 1));
    stats[n] = { number: n, frequency: freq, gap, avgGap, heatScore: heat };
  }

  // 拖牌補強 heat
  if (records.length >= 2) {
    const lastNums = new Set(records[0].numbers);
    for (let i = records.length - 1; i > 0; i--) {
      const match = records[i].numbers.filter(n => lastNums.has(n)).length;
      if (match >= 5) {
        for (const n of records[i - 1].numbers) {
          const tp = Math.min(0.5, match / 20);
          const s  = stats[n];
          const mb = s.gap >= 1 && s.gap <= 3 ? 0.2 : 0;
          s.heatScore = Math.min(1, s.heatScore * 0.7 + tp * 0.2 + mb * 0.1);
        }
      }
    }
  }
  return { stats, rawFreq, N };
}

/** 前N名熱/冷號碼 */
function hotCold(stats) {
  const arr = Object.values(stats).sort((a, b) => b.frequency - a.frequency);
  return {
    hotNumbers:  arr.slice(0, 20).map(s => s.number).sort((a, b) => a - b),
    coldNumbers: arr.slice(-20).map(s => s.number).sort((a, b) => a - b),
  };
}

/** 配對分析 */
function pairAnalysis(records, N) {
  const pairCount = {};
  for (const r of records) {
    const nums = [...r.numbers].sort((a, b) => a - b);
    for (let i = 0; i < nums.length; i++)
      for (let j = i + 1; j < nums.length; j++) {
        const k = nums[i] * 100 + nums[j];
        pairCount[k] = (pairCount[k] || 0) + 1;
      }
  }
  return Object.entries(pairCount)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 30)
    .map(([k, count]) => ({
      a: Math.floor(+k / 100), b: +k % 100,
      count, rate: count / N,
    }));
}

/** 組合統計 (size=2/3/4) */
function comboStats(records, size, top = 12) {
  const occur = {};
  function dfs(nums, start, path, idx) {
    if (path.length === size) {
      const key = path.join('-');
      if (!occur[key]) occur[key] = [];
      occur[key].push(idx);
      return;
    }
    for (let i = start; i <= nums.length - (size - path.length); i++) {
      path.push(nums[i]);
      dfs(nums, i + 1, path, idx);
      path.pop();
    }
  }
  for (let i = 0; i < records.length; i++) {
    const nums = [...records[i].numbers].sort((a, b) => a - b);
    dfs(nums, 0, [], i);
  }
  const result = [];
  for (const [key, idxs] of Object.entries(occur)) {
    idxs.sort((a, b) => a - b);
    const count  = idxs.length;
    const gap    = idxs[0];
    const avgGap = count <= 1 ? records.length
      : idxs.slice(0, -1).reduce((s, v, i) => s + (idxs[i + 1] - v), 0) / (count - 1);
    const suggestAfter = gap >= avgGap * 1.15 ? 0 : Math.max(0, Math.ceil(avgGap - gap));
    result.push({ numbers: key.split('-').map(Number), count, gap, avgGap, suggestAfter });
  }
  result.sort((a, b) => (b.count * 2 + b.gap / Math.max(1, b.avgGap)) - (a.count * 2 + a.gap / Math.max(1, a.avgGap)));
  return result.slice(0, top);
}

/** 8維評分核心 */
function computePredictScores(records, stats, rawFreq, N, strategyMode, zoneMultipliers, twoCombos, threeCombos, fourCombos) {
  const scores = new Array(81).fill(0);

  // ── Part 1: 拖牌法 Lag-N ──────────────────────────────────────────
  const maxLag = Math.min(10, N - 1);
  for (let lag = 1; lag <= maxLag; lag++) {
    const fromToCount = {}, fromTotal = {};
    for (let i = 0; i + lag < N; i++) {
      const toSet = new Set(records[i].numbers);
      for (const from of records[i + lag].numbers) {
        fromTotal[from] = (fromTotal[from] || 0) + 1;
        if (!fromToCount[from]) fromToCount[from] = {};
        for (const to of toSet) fromToCount[from][to] = (fromToCount[from][to] || 0) + 1;
      }
    }
    if (lag - 1 >= N) continue;
    const lagWeight = 1 / lag;
    for (const fromNum of records[lag - 1].numbers) {
      const total = fromTotal[fromNum] || 0;
      if (total < 5) continue;
      const toMap = fromToCount[fromNum] || {};
      for (const [to, cnt] of Object.entries(toMap)) {
        const rate = cnt / total;
        if (rate >= 0.15) scores[+to] += rate * lagWeight * 20;
      }
    }
  }

  // 自適應策略倍率
  const wTransition = strategyMode === 'transition' ? 1.8 : strategyMode === 'frequency' ? 0.6 : strategyMode === 'gap' ? 0.7 : 1.0;
  const wGap        = strategyMode === 'gap' ? 2.2 : strategyMode === 'transition' ? 0.6 : strategyMode === 'frequency' ? 0.5 : 1.0;
  const wHeat       = strategyMode === 'frequency' ? 2.0 : strategyMode === 'gap' ? 0.5 : strategyMode === 'transition' ? 0.7 : 1.0;

  for (let n = 1; n <= 80; n++) scores[n] *= wTransition;

  // ── Part 2: 同出到期 ──────────────────────────────────────────────
  for (const c of twoCombos)   if (c.suggestAfter === 0 && c.count >= 3) for (const n of c.numbers) scores[n] += c.count * 2.5;
  for (const c of threeCombos) if (c.suggestAfter === 0 && c.count >= 2) for (const n of c.numbers) scores[n] += c.count * 4.0;
  for (const c of fourCombos)  if (c.suggestAfter === 0)                 for (const n of c.numbers) scores[n] += c.count * 6.0;

  // ── Part 3: 個人間隔到期 ──────────────────────────────────────────
  for (let n = 1; n <= 80; n++) {
    const s = stats[n];
    if (s.gap >= s.avgGap) scores[n] += Math.min(s.gap - s.avgGap, 20) * 1.5 * wGap;
  }

  // ── Part 4: 指數衰減熱度 ─────────────────────────────────────────
  for (let n = 1; n <= 80; n++) scores[n] += stats[n].heatScore * 8 * wHeat;

  // ── Part 4b: 區間乘數 ────────────────────────────────────────────
  if (zoneMultipliers && Object.keys(zoneMultipliers).length > 0) {
    for (let n = 1; n <= 80; n++) {
      const z = Math.floor((n - 1) / 10);
      scores[n] *= zoneMultipliers[z] || 1.0;
    }
  }

  // ── Part 5: 連開熱勢 ─────────────────────────────────────────────
  const streak5 = new Array(81).fill(0);
  for (const r of records.slice(0, 5)) for (const n of r.numbers) streak5[n]++;
  for (let n = 1; n <= 80; n++) {
    const cnt = streak5[n];
    if (cnt >= 3) scores[n] += cnt * 9;
    else if (cnt === 2) scores[n] += cnt * 4.5;
  }

  // ── Part 6: 區間熱度 ─────────────────────────────────────────────
  const zoneCount = new Array(8).fill(0);
  for (let i = 0; i < Math.min(10, N); i++) {
    const w = Math.exp(-0.10 * i);
    for (const n of records[i].numbers) zoneCount[Math.floor((n - 1) / 10)] += w;
  }
  const maxZone = Math.max(...zoneCount, 0.1);
  for (let n = 1; n <= 80; n++) scores[n] += (zoneCount[Math.floor((n - 1) / 10)] / maxZone) * 5;

  // ── Part 7: 共現親合力 (Jaccard) ─────────────────────────────────
  const coLimit = Math.min(30, N);
  const coOccur = {};
  for (let i = 0; i < coLimit; i++) {
    const nums = records[i].numbers;
    for (let j = 0; j < nums.length; j++)
      for (let k = j + 1; k < nums.length; k++) {
        const [a, b] = [nums[j], nums[k]];
        if (!coOccur[a]) coOccur[a] = {};
        if (!coOccur[b]) coOccur[b] = {};
        coOccur[a][b] = (coOccur[a][b] || 0) + 1;
        coOccur[b][a] = (coOccur[b][a] || 0) + 1;
      }
  }
  const seedSorted = scores.map((v, i) => [i, v]).slice(1).sort((a, b) => b[1] - a[1]);
  const seeds = new Set(seedSorted.slice(0, 20).map(([n]) => n));
  for (let n = 1; n <= 80; n++) {
    const nFreq = Math.max(rawFreq[n], 1);
    let affinity = 0, pairCount = 0;
    for (const seed of seeds) {
      const co = (coOccur[seed] && coOccur[seed][n]) || 0;
      if (co > 0) {
        affinity += co / Math.sqrt(nFreq * Math.max(rawFreq[seed], 1));
        pairCount++;
      }
    }
    if (pairCount > 0) scores[n] += (affinity / seeds.size) * 18;
    else scores[n] -= 2;
  }

  // ── Part 8: 歷史命中強化 ─────────────────────────────────────────
  if (N >= 6) {
    for (let lag = 1; lag <= Math.min(5, N - 1); lag++) {
      const hist = records.slice(lag);
      if (hist.length < 15) break;
      const qs = new Array(81).fill(0);
      const prev = hist[0].numbers;
      const fromTotal2 = {}, toCount2 = {};
      for (let i = 1; i < hist.length; i++) {
        for (const f of hist[i].numbers) {
          fromTotal2[f] = (fromTotal2[f] || 0) + 1;
          if (!toCount2[f]) toCount2[f] = {};
          for (const t of hist[i - 1].numbers) toCount2[f][t] = (toCount2[f][t] || 0) + 1;
        }
      }
      for (const f of prev) {
        const tot = fromTotal2[f] || 0;
        if (tot < 3) continue;
        for (const [t, cnt] of Object.entries(toCount2[f] || {})) qs[+t] += cnt / tot;
      }
      for (let n = 1; n <= 80; n++) qs[n] += stats[n].heatScore * 3;
      const qSorted = qs.map((v, i) => [i, v]).slice(1).sort((a, b) => b[1] - a[1]);
      const predicted = new Set(qSorted.slice(0, 15).map(([n]) => n));
      const actualSet = new Set(records[lag - 1].numbers);
      const reward = Math.exp(-0.35 * (lag - 1)) * 7;
      for (const h of [...predicted].filter(n => actualSet.has(n))) scores[h] += reward;
    }
  }

  return scores;
}

/** 走勢分析 */
function trendAnalysis(records) {
  if (records.length < 6) return {};
  const zone4 = n => Math.floor((n - 1) / 20);
  const zone8 = n => Math.floor((n - 1) / 10);
  const r5 = records.slice(0, 5), r10 = records.slice(0, 10), r20 = records.slice(0, 20);

  const zf5 = [0,0,0,0], zf20 = [0,0,0,0];
  for (const r of r5)  for (const n of r.numbers) zf5[zone4(n)]++;
  for (const r of r20) for (const n of r.numbers) zf20[zone4(n)]++;

  const coldestZone = zf20.indexOf(Math.min(...zf20));
  const hottestZone = zf20.indexOf(Math.max(...zf20));

  // 8區週期
  const zf8_10 = new Array(8).fill(0), zf8_5 = new Array(8).fill(0);
  for (const r of r10) for (const n of r.numbers) zf8_10[zone8(n)]++;
  for (const r of r5)  for (const n of r.numbers) zf8_5[zone8(n)]++;

  const zone8History = r10.map(r => {
    const z = new Array(8).fill(0);
    for (const n of r.numbers) z[zone8(n)]++;
    return z;
  });

  const zone8CycleScore = zf8_10.map((cnt, z) => {
    const avg = zf8_10.reduce((s, c) => s + c, 0) / 8;
    return avg > 0 ? 1 - cnt / (avg * 2) : 0;
  });

  const dueZone8 = zone8CycleScore.indexOf(Math.max(...zone8CycleScore));

  return { zf5, zf20, coldestZone, hottestZone, zf8_10, zf8_5, zone8History, zone8CycleScore, dueZone8 };
}

// ── API 端點 ──────────────────────────────────────────────────────────────

/**
 * POST /api/bingo/analyze
 * Body: { records: [{drawNo, numbers: [...], drawTime}], strategyMode?, zoneMultipliers? }
 * 或不帶 records 則從 DB 讀最新 120 局
 */
router.post('/analyze', async (req, res) => {
  try {
    const pool = req.app.get('pool');
    let records = req.body.records;

    if (!records || records.length === 0) {
      const [rows] = await pool.query(
        'SELECT draw_no, numbers, draw_time FROM bingo_draws ORDER BY draw_no DESC LIMIT 120'
      );
      records = rows.map(r => ({
        drawNo: r.draw_no,
        numbers: JSON.parse(r.numbers),
        drawTime: r.draw_time,
      }));
    }

    if (records.length === 0) return res.json({ error: '無賓果資料', recommended: [], baseScores: {} });

    const strategyMode    = req.body.strategyMode || 'balanced';
    const zoneMultipliers = req.body.zoneMultipliers || {};

    const work = records.slice(0, 60);
    const { stats, rawFreq, N } = buildStats(work);
    const { hotNumbers, coldNumbers } = hotCold(stats);
    const topPairs    = pairAnalysis(work, N);
    const twoCombos   = comboStats(work, 2, 12);
    const threeCombos = comboStats(work, 3, 12);
    const fourCombos  = comboStats(work, 4, 12);

    const scoreArr = computePredictScores(work, stats, rawFreq, N, strategyMode, zoneMultipliers, twoCombos, threeCombos, fourCombos);
    const baseScores = {};
    for (let n = 1; n <= 80; n++) baseScores[n] = scoreArr[n];

    // 最終推薦 top-20
    const sorted = scoreArr.map((v, i) => [i, v]).slice(1).sort((a, b) => b[1] - a[1]);
    const recommended = sorted.slice(0, 20).map(([n]) => n).sort((a, b) => a - b);

    // 下一期期號
    const latestRecord = records[0];
    const nextDrawNo   = (latestRecord?.drawNo || 0) + 1;

    const trend = trendAnalysis(work);

    res.json({
      recommended,
      hotNumbers,
      coldNumbers,
      topPairs:     topPairs.slice(0, 10),
      nextDrawNo,
      analyzedDraws: N,
      strategy: `後端8維評分 (${strategyMode})`,
      baseScores,
      trendAnalysis: trend,
      topTwoCombos:   twoCombos,
      topThreeCombos: threeCombos,
      topFourCombos:  fourCombos,
      stats: Object.fromEntries(Object.entries(stats).map(([k, v]) => [k, {
        number: v.number, frequency: v.frequency, gap: v.gap,
        avgGap: v.avgGap, heatScore: v.heatScore,
      }])),
    });
  } catch (e) {
    console.error('[bingo/analyze]', e);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
