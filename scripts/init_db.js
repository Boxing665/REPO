/**
 * 初始化 MySQL 資料庫
 * 執行: node scripts/init_db.js
 */
require('dotenv').config();
const mysql = require('mysql2/promise');
const fs    = require('fs');
const path  = require('path');

async function main() {
  const conn = await mysql.createConnection({
    host:     process.env.MYSQL_HOST     || 'localhost',
    port:     parseInt(process.env.MYSQL_PORT || '3306'),
    user:     process.env.MYSQL_USER     || 'root',
    password: process.env.MYSQL_PASSWORD || '',
    multipleStatements: true,
  });

  console.log('✅ MySQL 連線成功');

  // 執行主 schema（CREATE DATABASE + 所有 TABLE + 初始資料）
  const schema = fs.readFileSync(
    path.join(__dirname, '..', 'database', 'schema.sql'),
    'utf8'
  );
  await conn.query(schema);
  console.log('✅ my_database 和所有資料表建立完成');

  // 如果是舊版資料庫，嘗試執行 migration 補齊缺少的欄位
  const migPath = path.join(__dirname, '..', 'database', 'migrate.sql');
  if (fs.existsSync(migPath)) {
    try {
      const migration = fs.readFileSync(migPath, 'utf8');
      await conn.query(migration);
      console.log('✅ migration.sql 執行完成');
    } catch (e) {
      console.warn('⚠️  migration 部分失敗（可忽略）:', e.message);
    }
  }

  await conn.end();
  console.log('\n🎉 資料庫初始化完成！');
  console.log('   現在可以 npm start 啟動 API server\n');
}

main().catch(e => { console.error('❌ 失敗:', e.message); process.exit(1); });
