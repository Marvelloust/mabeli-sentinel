import crypto from 'crypto';

export function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

export function generateApiKey() {
  return `ms_${crypto.randomBytes(30).toString('hex')}`;
}
