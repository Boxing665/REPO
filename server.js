const express = require('express');
const cors = require('cors');
const app = express();

// 1. 允許跨網域請求
app.use(cors({
  origin: ['https://pangpangsport.zeabur.app', 'http://localhost:3000', 'http://localhost:8080'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: true,
}));
app.options('*', cors());

// 2. 讓後端可以解析前端傳過來的 JSON 資料
app.use(express.json());

// 3. 設定一個「接收郵件」的路由 (API Endpoint)
app.post('/api/submit-email', (req, res) => {
    const userEmail = req.body.email; // 接收前端傳來的 email

    if (!userEmail) {
        return res.status(400).json({ success: false, message: '請輸入郵件！' });
    }

    console.log(`收到使用者的郵件了: ${userEmail}`);

    // 在這裡你可以把 email 存進資料夾、資料庫，或是寄信
    // 目前我們先簡單回傳成功訊息給前端
    res.json({ success: true, message: '後端已成功收到郵件！' });
});

// 4. 重要！Zeabur 部署必須使用 process.env.PORT 搭配 0.0.0.0
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`後端伺服器成功啟動在 Port: ${PORT}`);
});
