-- ============================================================
-- Migration：補齊舊版資料庫缺少的欄位
-- 執行: node scripts/init_db.js（自動包含此檔案）
-- ============================================================

USE my_database;

-- users 補 name 欄（若不存在）
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='name');
SET @sql = IF(@col=0,
  'ALTER TABLE users ADD COLUMN name VARCHAR(255) NULL AFTER email',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 移除廢棄的 two_factor 欄
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='two_factor_secret');
SET @sql = IF(@col>0,
  'ALTER TABLE users DROP COLUMN two_factor_secret',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='two_factor_enabled');
SET @sql = IF(@col>0,
  'ALTER TABLE users DROP COLUMN two_factor_enabled',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='two_factor_verified_at');
SET @sql = IF(@col>0,
  'ALTER TABLE users DROP COLUMN two_factor_verified_at',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- 移除廢棄的 subscription_* 欄
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='subscription_plan');
SET @sql = IF(@col>0,
  'ALTER TABLE users DROP COLUMN subscription_plan',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='users' AND COLUMN_NAME='subscription_expires_at');
SET @sql = IF(@col>0,
  'ALTER TABLE users DROP COLUMN subscription_expires_at',
  'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ── 2024-migrate: 新增 prediction_weekly_summary 與 prediction_analysis_detail ──
-- 在現有資料庫上執行一次即可

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

-- prediction_logs 新增 expires_at 欄（若不存在）
SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='prediction_logs' AND COLUMN_NAME='expires_at');
SET @sql2 = IF(@col2=0,
  'ALTER TABLE prediction_logs ADD COLUMN expires_at DATETIME NULL COMMENT \'8天後到期，自動清除\' AFTER updated_at',
  'SELECT 1');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;

-- 為 expires_at 加索引（若不存在）
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA='my_database' AND TABLE_NAME='prediction_logs' AND INDEX_NAME='idx_expires');
SET @sql3 = IF(@idx=0,
  'ALTER TABLE prediction_logs ADD INDEX idx_expires (expires_at)',
  'SELECT 1');
PREPARE stmt3 FROM @sql3; EXECUTE stmt3; DEALLOCATE PREPARE stmt3;
