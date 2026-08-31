-- ============================================================
-- 胖胖體育 MySQL 資料庫 Schema
-- Database: my_database
-- ============================================================

CREATE DATABASE IF NOT EXISTS my_database
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE my_database;

-- ── 系統設定（管理者密碼等）────────────────────────────────────
CREATE TABLE IF NOT EXISTS app_config (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  key_name    VARCHAR(100) NOT NULL UNIQUE,
  value_enc   TEXT         NOT NULL COMMENT '加密儲存的設定值',
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 用戶 / 訂閱管理 ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  email           VARCHAR(255) NOT NULL UNIQUE,
  name            VARCHAR(255) NULL,
  auth_expires_at DATETIME     NULL COMMENT 'NULL = 永久訂閱',
  is_active       BOOLEAN      DEFAULT TRUE,
  created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 付款訂單 ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payment_orders (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  order_no        VARCHAR(50)  NOT NULL UNIQUE COMMENT 'ECPay MerchantTradeNo',
  user_email_enc  TEXT         NOT NULL COMMENT 'AES 加密的 Email',
  plan_name       VARCHAR(100) NOT NULL,
  amount          INT          NOT NULL,
  months          TINYINT      NOT NULL,
  status          VARCHAR(20)  NOT NULL DEFAULT 'pending' COMMENT 'pending/paid/failed',
  paid_at         DATETIME     NULL,
  created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_order_no (order_no),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 預測記錄（體育 / 樂透 / 賓果 統一）──────────────────────
CREATE TABLE IF NOT EXISTS prediction_logs (
  id               VARCHAR(255) PRIMARY KEY,
  type             ENUM('sport','lottery','bingo') NOT NULL,
  title            VARCHAR(500) NOT NULL,
  subtitle         VARCHAR(500),
  predicted_result TEXT         NOT NULL,
  actual_result    TEXT         NULL,
  outcome          ENUM('pending','correct','partial','incorrect') DEFAULT 'pending',
  details          JSON,
  created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_type_created (type, created_at DESC),
  INDEX idx_outcome (outcome)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 539 AI 推薦記錄（每日彩球預測快照）──────────────────────
CREATE TABLE IF NOT EXISTS lottery_539_predictions (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_date   DATE         NOT NULL UNIQUE,
  numbers     JSON         NOT NULL COMMENT '[n1,n2,n3,n4,n5]',
  reasons     JSON         COMMENT '{號碼:來源說明}',
  math_stats  JSON         COMMENT '{p5,p4,p3,p2,p1,expectedHits,...}',
  newspaper   JSON         COMMENT '當日報紙原始數據快照',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_draw_date (draw_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 539 開獎歷史 ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lottery_draws_539 (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_date   VARCHAR(10)  NOT NULL UNIQUE COMMENT 'MM/DD',
  numbers     JSON         NOT NULL COMMENT '[n1,n2,n3,n4,n5]',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_date (draw_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 大樂透開獎歷史 ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lottery_draws_lotto (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_date   VARCHAR(10)  NOT NULL UNIQUE COMMENT 'MM/DD',
  numbers     JSON         NOT NULL COMMENT '[n1..n6] 1-49',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_date (draw_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 威力彩開獎歷史 ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lottery_draws_power (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_date   VARCHAR(10)  NOT NULL UNIQUE COMMENT 'MM/DD',
  numbers     JSON         NOT NULL COMMENT '[n1..n6] 前區1-38',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_date (draw_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 賓果賓果開獎歷史 ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bingo_draws (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_no     INT          NOT NULL UNIQUE COMMENT '期號',
  numbers     JSON         NOT NULL COMMENT '[n1..n20] 1-80',
  draw_time   DATETIME     NULL,
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_draw_no (draw_no DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 體育比賽記錄 ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sports_matches (
  id          VARCHAR(255) PRIMARY KEY,
  home_team   VARCHAR(255) NOT NULL,
  away_team   VARCHAR(255) NOT NULL,
  league      VARCHAR(255),
  sport_type  VARCHAR(50)  COMMENT 'football/basketball/baseball',
  match_time  DATETIME,
  home_score  SMALLINT     NULL,
  away_score  SMALLINT     NULL,
  status      VARCHAR(50)  DEFAULT 'scheduled',
  odds_data   JSON         COMMENT '{homeWin, awayWin, draw, overLine}',
  prediction  JSON         COMMENT '{predictedHome, predictedAway, confidence, winner}',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_sport_time (sport_type, match_time DESC),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 體育預測邏輯快照（MLB ERA / 大小分等）────────────────────
CREATE TABLE IF NOT EXISTS sports_predictions (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  match_date      DATE         NOT NULL,
  sport           VARCHAR(20)  NOT NULL DEFAULT 'MLB',
  home_team       VARCHAR(80)  NOT NULL,
  away_team       VARCHAR(80)  NOT NULL,
  prediction_data JSON         COMMENT '{era, bullpenEra, expRuns, overUnder, ...}',
  created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_match_date (match_date),
  INDEX idx_sport (sport)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 球隊連戰疲勞記錄 ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sports_rest_games (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  team        VARCHAR(100) NOT NULL,
  sport       VARCHAR(50)  NOT NULL,
  rest_days   TINYINT      NOT NULL DEFAULT 0,
  last_game   DATE         NULL,
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_team_sport (team, sport)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 報紙預測（今彩539小黃單）────────────────────────────────
CREATE TABLE IF NOT EXISTS newspaper_539 (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  draw_date   VARCHAR(10)  NOT NULL UNIQUE COMMENT 'MM/DD',
  gu_zhi      TINYINT      NOT NULL COMMENT '孤支',
  er_zhong    JSON         NOT NULL COMMENT '二中一 [n1,n2]',
  san_zhong   JSON         NOT NULL COMMENT '三中一 [n1,n2,n3]',
  xique       JSON         NOT NULL COMMENT '喜雀神卦 [n1,n2,n3]',
  tiangan     JSON         NOT NULL COMMENT '天干地支 [n1,n2,n3,n4]',
  bagua       JSON         NOT NULL COMMENT '八卦尾數 [n1,n2,n3]',
  banlu       JSON         NOT NULL COMMENT '版路尾數 [n1,n2,n3]',
  toucai1     JSON         COMMENT '頭彩五連碰A',
  toucai2     JSON         COMMENT '頭彩五連碰B',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_date (draw_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 拖牌分析 ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS drag_patterns_539 (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  drag_number  TINYINT      NOT NULL UNIQUE,
  interval_avg FLOAT        NOT NULL DEFAULT 0,
  current_gap  INT          NOT NULL DEFAULT 0,
  is_due_next  BOOLEAN      DEFAULT FALSE,
  hit_rate     FLOAT        DEFAULT 0,
  updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_due (is_due_next)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── AI 自我學習策略權重 ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_weights (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  category    VARCHAR(100) NOT NULL UNIQUE,
  strategy    VARCHAR(100) DEFAULT 'balanced',
  weights     JSON         NOT NULL,
  hit_records JSON         COMMENT '[{strategy, hits, timestamp}, ...]',
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── 圖表分析快取 ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chart_cache (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  chart_type  VARCHAR(100) NOT NULL UNIQUE,
  data        JSON         NOT NULL,
  expires_at  DATETIME     NOT NULL,
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Whitebear 私人金庫（AES-256-GCM 加密）────────────────────
CREATE TABLE IF NOT EXISTS whitebear_vault (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  category    VARCHAR(80)  NOT NULL DEFAULT 'general',
  title       VARCHAR(200) NOT NULL,
  content_enc LONGTEXT     NOT NULL COMMENT 'AES-256-GCM 加密內容',
  created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='私人金庫 - AES-256-GCM 加密';

-- ── 初始策略權重（若不存在則插入）───────────────────────────
INSERT IGNORE INTO learning_weights (category, strategy, weights, hit_records) VALUES
  ('539',              'balanced',   '{"hot":1.0,"cold":0.8,"gap":1.2,"newspaper":1.5}', '[]'),
  ('bingo',            'zone_a',     '{"zone_a":1.2,"zone_b":1.0,"carry":1.1}', '[]'),
  ('sport_football',   'strategy_b', '{"form":1.2,"home_adv":1.1,"odds":0.9}', '[]'),
  ('sport_basketball', 'strategy_b', '{"form":1.1,"away_pen":0.9,"pace":1.0}', '[]');

-- ── 每週預測準確率彙總（7天一結算）────────────────────────────────
CREATE TABLE IF NOT EXISTS prediction_weekly_summary (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  week_start    DATE         NOT NULL         COMMENT '該週週一日期',
  category      VARCHAR(50)  NOT NULL         COMMENT 'sport / lottery_539 / lottery_lotto / lottery_power / bingo',
  sub_category  VARCHAR(100) DEFAULT ''       COMMENT '細分：MLB/NBA/足球 或 熱號/冷號/遺漏 等',
  total_count   INT          DEFAULT 0        COMMENT '本週總預測筆數',
  hit_count     INT          DEFAULT 0        COMMENT '命中（correct）',
  partial_count INT          DEFAULT 0        COMMENT '部分命中（partial）',
  miss_count    INT          DEFAULT 0        COMMENT '未命中（incorrect）',
  pending_count INT          DEFAULT 0        COMMENT '尚未有結果（pending）',
  hit_rate      FLOAT        DEFAULT 0        COMMENT '命中率 = (hit + partial*0.5) / judged',
  top_signal    VARCHAR(200) DEFAULT ''       COMMENT '本週最準確的分析訊號',
  worst_signal  VARCHAR(200) DEFAULT ''       COMMENT '本週最不準確的訊號',
  analysis_note TEXT                          COMMENT '自動產生的週報備註',
  created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_week_cat (week_start, category),
  INDEX idx_week_start (week_start DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='每週預測準確率彙總 — 每日自動計算，保留52週';

-- ── 預測詳細分析紀錄（每筆預測的完整邏輯快照）────────────────────
CREATE TABLE IF NOT EXISTS prediction_analysis_detail (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  log_id          VARCHAR(255) NOT NULL            COMMENT '對應 prediction_logs.id',
  category        VARCHAR(50)  NOT NULL            COMMENT 'sport / lottery_539 / bingo 等',
  sub_category    VARCHAR(100) DEFAULT ''          COMMENT '細分類別（MLB / 熱號分析 / 動畫特徵 等）',
  home_team       VARCHAR(100) DEFAULT ''          COMMENT '（體育）主隊',
  away_team       VARCHAR(100) DEFAULT ''          COMMENT '（體育）客隊',
  sport_type      VARCHAR(50)  DEFAULT ''          COMMENT '（體育）球種',
  draw_date       VARCHAR(20)  DEFAULT ''          COMMENT '（樂透）開獎日期',
  draw_no         INT          DEFAULT 0           COMMENT '（賓果）期號',
  predicted_nums  JSON                             COMMENT '預測號碼清單',
  actual_nums     JSON                             COMMENT '實際開獎號碼',
  hit_count       TINYINT      DEFAULT 0           COMMENT '命中顆數',
  signal_breakdown JSON                            COMMENT '各訊號詳細分析（ERA/勝率/遺漏/熱號等）',
  confidence      FLOAT        DEFAULT 0           COMMENT '信心分數 0-1',
  outcome         VARCHAR(20)  DEFAULT ''          COMMENT 'correct/partial/incorrect/pending',
  expires_at      DATETIME                         COMMENT '8天後自動清除',
  created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_log_id (log_id),
  INDEX idx_category_date (category, created_at DESC),
  INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='每筆預測的完整分析邏輯快照 — 保留8天，自動清除';
