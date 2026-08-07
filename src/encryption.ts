import { createCipheriv, createDecipheriv, scryptSync, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';

export function encrypt(plaintext: string, keySecret: string): string {
  const key = scryptSync(keySecret, 'eap-salt', 32);
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

export function decrypt(encoded: string, keySecret: string): string {
  const key = scryptSync(keySecret, 'eap-salt', 32);
  const [ivHex, authTagHex, encrypted] = encoded.split(':');
  if (!ivHex || !authTagHex || encrypted === undefined) throw new Error('Invalid encrypted payload');
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
