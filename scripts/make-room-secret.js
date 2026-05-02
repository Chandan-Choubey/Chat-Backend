import { createAccessProof, createScryptHash } from '../src/secure-room.js';

const [passphrase, roomId = process.env.CHAT_ROOM_ID || 'private-room'] = process.argv.slice(2);

if (!passphrase || passphrase.length < 16) {
  console.error('Usage: npm run make-secret -- "a long shared passphrase" [room-id]');
  console.error('The passphrase must be at least 16 characters.');
  process.exit(1);
}

if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{2,63}$/.test(roomId)) {
  console.error('Room id must be 3-64 characters and use letters, numbers, underscores, or hyphens.');
  process.exit(1);
}

const accessProof = createAccessProof(roomId, passphrase);
const accessProofHash = createScryptHash(accessProof);

console.log(`CHAT_ROOM_ID=${roomId}`);
console.log(`CHAT_ACCESS_PROOF_HASH=${accessProofHash}`);

