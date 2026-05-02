import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(crypto.scrypt);

const SCRYPT_PARAMS = Object.freeze({
  N: 32768,
  r: 8,
  p: 1,
  keyLength: 32,
  maxmem: 80 * 1024 * 1024
});

const ACCESS_PROOF_PREFIX = 'two-person-chat:v1:access';

export function createAccessProof(roomId, passphrase) {
  return crypto
    .createHash('sha256')
    .update(`${ACCESS_PROOF_PREFIX}:${roomId}:${passphrase}`, 'utf8')
    .digest('base64url');
}

export function createScryptHash(secret) {
  const salt = crypto.randomBytes(16).toString('base64url');
  const hash = crypto.scryptSync(secret, salt, SCRYPT_PARAMS.keyLength, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_PARAMS.maxmem
  });

  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt,
    hash.toString('base64url')
  ].join('$');
}

export function isScryptHash(value) {
  try {
    parseScryptHash(value);
    return true;
  } catch {
    return false;
  }
}

export async function verifyAccessProof(accessProof, { accessProofHash, password, roomId }) {
  if (typeof accessProof !== 'string' || accessProof.length < 32 || accessProof.length > 128) {
    return false;
  }

  if (accessProofHash) {
    return verifyScryptHash(accessProof, accessProofHash);
  }

  if (!password) {
    return false;
  }

  const expectedProof = createAccessProof(roomId, password);
  return timingSafeEqualText(accessProof, expectedProof);
}

async function verifyScryptHash(secret, encodedHash) {
  const parsed = parseScryptHash(encodedHash);
  const expected = Buffer.from(parsed.hash, 'base64url');
  const actual = await scryptAsync(secret, parsed.salt, expected.length, {
    N: parsed.N,
    r: parsed.r,
    p: parsed.p,
    maxmem: SCRYPT_PARAMS.maxmem
  });

  return timingSafeEqualBuffer(Buffer.from(actual), expected);
}

function parseScryptHash(value) {
  if (typeof value !== 'string') {
    throw new Error('Hash must be a string.');
  }

  const [scheme, N, r, p, salt, hash] = value.split('$');
  const parsed = {
    scheme,
    N: Number(N),
    r: Number(r),
    p: Number(p),
    salt,
    hash
  };

  if (
    parsed.scheme !== 'scrypt' ||
    !Number.isInteger(parsed.N) ||
    !Number.isInteger(parsed.r) ||
    !Number.isInteger(parsed.p) ||
    parsed.N < 16384 ||
    parsed.r < 8 ||
    parsed.p < 1 ||
    typeof parsed.salt !== 'string' ||
    parsed.salt.length < 16 ||
    typeof parsed.hash !== 'string' ||
    parsed.hash.length < 32
  ) {
    throw new Error('Invalid scrypt hash format.');
  }

  return parsed;
}

function timingSafeEqualText(left, right) {
  return timingSafeEqualBuffer(Buffer.from(left), Buffer.from(right));
}

function timingSafeEqualBuffer(left, right) {
  if (left.length !== right.length) {
    crypto.timingSafeEqual(left, left);
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

