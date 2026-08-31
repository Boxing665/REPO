/**
 * AES-256-CBC 雙向加密工具
 * 用於 MySQL 敏感欄位（email、TOTP secret 等）
 */
const crypto = require('crypto');

const KEY = Buffer.from(
  (process.env.DB_ENCRYPT_KEY || 'PangPangSecure2026DBEncryptKey32').padEnd(32).slice(0, 32)
);
const IV_LENGTH = 16;

function encrypt(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text;
  try {
    const [ivHex, encHex] = text.split(':');
    const iv  = Buffer.from(ivHex, 'hex');
    const enc = Buffer.from(encHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch { return ''; }
}

// ECPay CheckMacValue 計算（SHA256）
function ecpayCheckMac(params, hashKey, hashIV) {
  const sorted = Object.keys(params).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
  let raw = `HashKey=${hashKey}&` + sorted.map(k => `${k}=${params[k]}`).join('&') + `&HashIV=${hashIV}`;
  raw = encodeURIComponent(raw)
    .replace(/%2d/gi, '-').replace(/%5f/gi, '_').replace(/%2e/gi, '.')
    .replace(/%21/gi, '!').replace(/%2a/gi, '*').replace(/%28/gi, '(')
    .replace(/%29/gi, ')').toLowerCase();
  return crypto.createHash('sha256').update(raw).digest('hex').toUpperCase();
}

module.exports = { encrypt, decrypt, ecpayCheckMac };
