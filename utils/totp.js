/**
 * Google Authenticator TOTP 工具
 * 使用 speakeasy 產生/驗證 TOTP
 */
const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');
const { encrypt, decrypt } = require('./encrypt');

const APP_NAME = '胖胖體育 PangPang';

/** 產生新的 TOTP secret 並回傳 QR code URL */
async function generateSetup(adminId) {
  const secret = speakeasy.generateSecret({
    name:   `${APP_NAME} (${adminId})`,
    length: 20,
  });

  const qrUrl = await QRCode.toDataURL(secret.otpauth_url);

  return {
    secretEnc:   encrypt(secret.base32),  // 加密後存資料庫
    secretBase32: secret.base32,          // 掃 QR 用（只在 setup 時顯示一次）
    otpauthUrl:  secret.otpauth_url,
    qrDataUrl:   qrUrl,                   // base64 QR 圖片
  };
}

/** 驗證使用者輸入的 6 位數 TOTP */
function verify(secretEnc, token) {
  const base32 = decrypt(secretEnc);
  if (!base32) return false;
  return speakeasy.totp.verify({
    secret:   base32,
    encoding: 'base32',
    token:    String(token).replace(/\s/g, ''),
    window:   1,  // 允許前後 30 秒誤差
  });
}

module.exports = { generateSetup, verify };
