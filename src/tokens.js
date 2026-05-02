import crypto from 'node:crypto';

export function createRoomToken({ roomId, displayName, ttlMs, secret }) {
  const expiresAt = Date.now() + ttlMs;
  const payload = {
    rid: roomId,
    sub: crypto.randomUUID(),
    name: displayName,
    exp: expiresAt
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = sign(encodedPayload, secret);

  return {
    token: `${encodedPayload}.${signature}`,
    expiresAt,
    userId: payload.sub
  };
}

export function verifyRoomToken(token, { roomId, secret }) {
  if (typeof token !== 'string') {
    throw new Error('Missing token.');
  }

  const [encodedPayload, signature, extra] = token.split('.');
  if (!encodedPayload || !signature || extra) {
    throw new Error('Invalid token.');
  }

  const expectedSignature = sign(encodedPayload, secret);
  if (!timingSafeEqualText(signature, expectedSignature)) {
    throw new Error('Invalid token signature.');
  }

  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
  if (payload.rid !== roomId) {
    throw new Error('Token room does not match.');
  }

  if (typeof payload.exp !== 'number' || payload.exp < Date.now()) {
    throw new Error('Token expired.');
  }

  if (!isUuid(payload.sub) || !isDisplayName(payload.name)) {
    throw new Error('Invalid token payload.');
  }

  return {
    roomId: payload.rid,
    userId: payload.sub,
    displayName: payload.name,
    expiresAt: payload.exp
  };
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function timingSafeEqualText(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    crypto.timingSafeEqual(leftBuffer, leftBuffer);
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isDisplayName(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= 32;
}

