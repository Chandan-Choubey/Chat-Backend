import crypto from 'node:crypto';
import http from 'node:http';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import { config } from './config.js';
import { pushNotificationsEnabled, sendIncomingMessagePush } from './push-notifications.js';
import { verifyAccessProof } from './secure-room.js';
import { createRoomToken, verifyRoomToken } from './tokens.js';

const app = express();
const server = http.createServer(app);
const participants = new Map();
const pushTokensByUser = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '4kb' }));

app.use(
  cors({
    origin: validateOrigin,
    methods: ['GET', 'POST'],
    credentials: false
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false
  })
);

if (config.requireHttps) {
  app.use((req, res, next) => {
    const forwardedProto = req.get('x-forwarded-proto');
    const protocol = forwardedProto || req.protocol;
    if (protocol === 'https') {
      next();
      return;
    }

    res.status(403).json({ error: 'HTTPS is required.' });
  });
}

const joinLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many access attempts. Try again later.' }
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    roomId: config.roomId,
    activeParticipants: participants.size,
    pushEnabled: pushNotificationsEnabled()
  });
});

app.post('/api/rooms/:roomId/join', joinLimiter, async (req, res) => {
  const requestedRoomId = req.params.roomId;
  if (requestedRoomId !== config.roomId) {
    res.status(404).json({ error: 'Room not found.' });
    return;
  }

  const displayName = normalizeDisplayName(req.body?.displayName);
  const accessProof = req.body?.accessProof;

  if (!displayName || typeof accessProof !== 'string') {
    res.status(400).json({ error: 'Display name and passphrase are required.' });
    return;
  }

  const proofIsValid = await verifyAccessProof(accessProof, {
    accessProofHash: config.accessProofHash,
    password: config.password,
    roomId: config.roomId
  });

  if (!proofIsValid) {
    res.status(401).json({ error: 'Invalid passphrase.' });
    return;
  }

  const token = createRoomToken({
    roomId: config.roomId,
    displayName,
    ttlMs: config.tokenTtlMs,
    secret: config.tokenSecret
  });

  res.json({
    token: token.token,
    expiresAt: new Date(token.expiresAt).toISOString(),
    roomId: config.roomId,
    displayName,
    capacity: config.roomCapacity
  });
});

app.post('/api/rooms/:roomId/push-token', authenticateRoomRequest, (req, res) => {
  const pushToken = normalizePushToken(req.body?.pushToken);
  if (!pushToken) {
    res.status(400).json({ error: 'Invalid push token.' });
    return;
  }

  removePushTokens([pushToken]);
  const userTokens = pushTokensByUser.get(req.roomUser.userId) || new Set();
  userTokens.add(pushToken);
  pushTokensByUser.set(req.roomUser.userId, userTokens);

  res.json({ ok: true, pushEnabled: pushNotificationsEnabled() });
});

app.delete('/api/rooms/:roomId/push-token', authenticateRoomRequest, (req, res) => {
  const pushToken = normalizePushToken(req.body?.pushToken);
  if (!pushToken) {
    pushTokensByUser.delete(req.roomUser.userId);
    res.json({ ok: true });
    return;
  }

  const userTokens = pushTokensByUser.get(req.roomUser.userId);
  if (userTokens) {
    userTokens.delete(pushToken);
    if (userTokens.size === 0) {
      pushTokensByUser.delete(req.roomUser.userId);
    }
  }

  res.json({ ok: true });
});

const io = new Server(server, {
  cors: {
    origin: config.clientOrigins,
    methods: ['GET', 'POST'],
    credentials: false
  },
  maxHttpBufferSize: 16 * 1024,
  serveClient: false
});

io.use((socket, next) => {
  try {
    const payload = verifyRoomToken(socket.handshake.auth?.token, {
      roomId: config.roomId,
      secret: config.tokenSecret
    });

    const isKnownParticipant = participants.has(payload.userId);
    if (!isKnownParticipant && participants.size >= config.roomCapacity) {
      next(new Error('This room already has two active participants.'));
      return;
    }

    socket.data.user = payload;
    next();
  } catch (error) {
    next(new Error(error.message || 'Unauthorized.'));
  }
});

io.on('connection', (socket) => {
  const user = socket.data.user;
  const participant = participants.get(user.userId) || {
    userId: user.userId,
    displayName: user.displayName,
    sockets: new Set()
  };

  participant.displayName = user.displayName;
  participant.sockets.add(socket.id);
  participants.set(user.userId, participant);

  socket.join(config.roomId);
  socket.emit('room:ready', {
    self: user.userId,
    users: listParticipants(),
    capacity: config.roomCapacity
  });
  broadcastPresence();

  socket.on('message:send', (payload = {}) => {
    const encrypted = normalizeEncryptedPayload(payload.encrypted);
    if (!encrypted) {
      socket.emit('message:error', { error: 'Invalid encrypted message.' });
      return;
    }

    const outgoingMessage = {
      id: cryptoRandomId(),
      senderId: user.userId,
      senderName: participant.displayName,
      encrypted,
      sentAt: new Date().toISOString()
    };

    io.to(config.roomId).emit('message:new', outgoingMessage);
    sendPushToOtherParticipants(user.userId, participant.displayName);
  });

  socket.on('typing', (payload = {}) => {
    socket.to(config.roomId).emit('typing', {
      userId: user.userId,
      displayName: participant.displayName,
      isTyping: Boolean(payload.isTyping)
    });
  });

  socket.on('disconnect', () => {
    const current = participants.get(user.userId);
    if (!current) {
      return;
    }

    current.sockets.delete(socket.id);
    if (current.sockets.size === 0) {
      participants.delete(user.userId);
    }

    broadcastPresence();
  });
});

server.listen(config.port, () => {
  console.log(`Secure chat backend listening on http://localhost:${config.port}`);
  console.log(`Room route: /chat/${config.roomId}`);
  console.log(`Allowed client origins: ${config.clientOrigins.join(', ')}`);
});

function broadcastPresence() {
  io.to(config.roomId).emit('room:presence', {
    users: listParticipants(),
    capacity: config.roomCapacity
  });
}

function authenticateRoomRequest(req, res, next) {
  if (req.params.roomId !== config.roomId) {
    res.status(404).json({ error: 'Room not found.' });
    return;
  }

  try {
    const token = bearerTokenFromHeader(req.get('authorization'));
    req.roomUser = verifyRoomToken(token, {
      roomId: config.roomId,
      secret: config.tokenSecret
    });
    next();
  } catch (error) {
    res.status(401).json({ error: error.message || 'Unauthorized.' });
  }
}

function bearerTokenFromHeader(value) {
  if (typeof value !== 'string') {
    throw new Error('Missing token.');
  }

  const [type, token, extra] = value.split(/\s+/);
  if (type !== 'Bearer' || !token || extra) {
    throw new Error('Invalid token.');
  }

  return token;
}

function sendPushToOtherParticipants(senderId, senderName) {
  const tokens = listPushTokensExcept(senderId);
  if (tokens.length === 0) {
    return;
  }

  sendIncomingMessagePush({
    tokens,
    roomId: config.roomId,
    senderName
  })
    .then(removePushTokens)
    .catch((error) => {
      console.warn(`Unable to send push notification: ${error.message}`);
    });
}

function listPushTokensExcept(senderId) {
  const tokens = [];
  for (const [userId, userTokens] of pushTokensByUser.entries()) {
    if (userId === senderId) {
      continue;
    }

    tokens.push(...userTokens);
  }

  return tokens;
}

function removePushTokens(tokens) {
  if (!Array.isArray(tokens) || tokens.length === 0) {
    return;
  }

  const invalidTokens = new Set(tokens);
  for (const [userId, userTokens] of pushTokensByUser.entries()) {
    for (const token of invalidTokens) {
      userTokens.delete(token);
    }

    if (userTokens.size === 0) {
      pushTokensByUser.delete(userId);
    }
  }
}

function listParticipants() {
  return [...participants.values()].map((participant) => ({
    userId: participant.userId,
    displayName: participant.displayName
  }));
}

function normalizeDisplayName(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const normalized = value.trim().replace(/\s+/g, ' ');
  if (normalized.length < 1 || normalized.length > 32) {
    return null;
  }

  return normalized;
}

function normalizePushToken(value) {
  if (typeof value !== 'string') {
    return null;
  }

  const token = value.trim();
  if (token.length < 20 || token.length > 4096 || !/^[a-zA-Z0-9:_-]+$/.test(token)) {
    return null;
  }

  return token;
}

function normalizeEncryptedPayload(encrypted) {
  if (!encrypted || typeof encrypted !== 'object') {
    return null;
  }

  const { iv, ciphertext } = encrypted;
  if (!isBase64Url(iv, 16, 32) || !isBase64Url(ciphertext, 16, config.encryptedMessageMaxLength)) {
    return null;
  }

  return { iv, ciphertext };
}

function isBase64Url(value, minLength, maxLength) {
  return (
    typeof value === 'string' &&
    value.length >= minLength &&
    value.length <= maxLength &&
    /^[a-zA-Z0-9_-]+$/.test(value)
  );
}

function validateOrigin(origin, callback) {
  if (!origin || config.clientOrigins.includes(origin)) {
    callback(null, true);
    return;
  }

  console.warn(`Rejected CORS origin: ${origin}`);
  callback(new Error('Origin is not allowed.'));
}

function cryptoRandomId() {
  return crypto.randomUUID();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  io.close();
  server.close(() => process.exit(0));
}
