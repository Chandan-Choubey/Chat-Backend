import admin from 'firebase-admin';
import { config } from './config.js';

const NOTIFICATION_BODY = 'you win an iphone';
let messaging = null;

if (config.firebaseServiceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(config.firebaseServiceAccount)
  });
  messaging = admin.messaging();
}

export function pushNotificationsEnabled() {
  return Boolean(messaging);
}

export async function sendIncomingMessagePush({ tokens, roomId, senderName }) {
  const uniqueTokens = [...new Set(tokens)].filter(Boolean).slice(0, 500);
  if (!messaging || uniqueTokens.length === 0) {
    return [];
  }

  const title = senderName ? `${senderName} sent a message` : 'New message';
  const response = await messaging.sendEachForMulticast({
    tokens: uniqueTokens,
    data: {
      title,
      body: NOTIFICATION_BODY,
      roomId,
      url: `/chat/${roomId}`
    },
    webpush: {
      notification: {
        title,
        body: NOTIFICATION_BODY,
        tag: 'secure-chat-message',
        renotify: true
      }
    }
  });

  return response.responses
    .map((result, index) => ({ result, token: uniqueTokens[index] }))
    .filter(({ result }) => tokenIsInvalid(result.error?.code))
    .map(({ token }) => token);
}

function tokenIsInvalid(code) {
  return (
    code === 'messaging/registration-token-not-registered' ||
    code === 'messaging/invalid-registration-token' ||
    code === 'messaging/invalid-argument'
  );
}
