import { WebSocketServer } from "ws";
import { v4 as uuidv4 } from "uuid";

import {
  getOrCreateUser,
  getOrCreateRoom,
  addUserToRoom,
  checkReplay,
  storeEvent,
  getRecentRoomEvents
} from "./db.js";

import {
  verifySignature,
  decryptPayload,
  canonicalizePacketForSigning
} from "./crypto.js";

const PORT = process.env.PORT || 8080;
const SERVER_TEST_KEY = process.env.CHAT_TEST_KEY;

if (!SERVER_TEST_KEY) {
  console.error("Missing CHAT_TEST_KEY environment variable.");
  process.exit(1);
}

const wss = new WebSocketServer({ port: PORT });
const clients = new Map();

function sendJson(ws, obj) {
  ws.send(JSON.stringify(obj));
}

function isValidPacket(packet) {
  return (
    packet &&
    typeof packet === "object" &&
    packet.version === 1 &&
    typeof packet.type === "string" &&
    typeof packet.sender === "string" &&
    typeof packet.room === "string" &&
    Number.isInteger(packet.counter) &&
    typeof packet.nonce === "string" &&
    typeof packet.ciphertext === "string" &&
    typeof packet.signature === "string"
  );
}

function broadcastToRoom(roomName, message) {
  for (const [, client] of clients) {
    if (client.room === roomName && client.ws.readyState === client.ws.OPEN) {
      sendJson(client.ws, message);
    }
  }
}

wss.on("connection", (ws) => {
  const clientId = uuidv4();

  clients.set(clientId, {
    ws,
    userId: null,
    username: null,
    roomId: null,
    room: null
  });

  sendJson(ws, {
    type: "server.hello",
    client_id: clientId,
    message: "Connected to zero-trust chat server"
  });

  ws.on("message", (raw) => {
    let packet;

    try {
      packet = JSON.parse(raw.toString());
    } catch {
      sendJson(ws, {
        type: "error",
        error: "Invalid JSON"
      });
      return;
    }

    if (!isValidPacket(packet)) {
      sendJson(ws, {
        type: "error",
        error: "Invalid packet structure"
      });
      return;
    }

    const user = getOrCreateUser(packet.sender);
    const room = getOrCreateRoom(packet.room);
    const client = clients.get(clientId);

    addUserToRoom(user.id, room.id);

    client.userId = user.id;
    client.username = user.username;
    client.roomId = room.id;
    client.room = room.name;

    if (!user.public_key) {
      sendJson(ws, {
        type: "error",
        error: "User has no public key registered"
      });
      return;
    }

    const signedData = canonicalizePacketForSigning(packet);

    const validSignature = verifySignature(
      user.public_key,
      signedData,
      packet.signature
    );

    if (!validSignature) {
      sendJson(ws, {
        type: "error",
        error: "Invalid message signature"
      });
      return;
    }

    if (!checkReplay(user.id, packet.counter)) {
      sendJson(ws, {
        type: "error",
        error: "Replay rejected: counter too old"
      });
      return;
    }

    let decryptedPayload;

    try {
      decryptedPayload = decryptPayload(
        SERVER_TEST_KEY,
        {
          nonce: packet.nonce,
          ciphertext: packet.ciphertext
        },
        {
          version: packet.version,
          type: packet.type,
          sender: packet.sender,
          room: packet.room,
          counter: packet.counter
        }
      );
    } catch {
      sendJson(ws, {
        type: "error",
        error: "Could not decrypt payload"
      });
      return;
    }

    const recentEvents = getRecentRoomEvents(room.id, 25);

    sendJson(ws, {
      type: "server.history",
      room: room.name,
      events: recentEvents.map((event) => ({
        id: event.id,
        type: event.type,
        sender: event.sender,
        counter: event.counter,
        payload: JSON.parse(event.payload),
        created_at: event.created_at
      }))
    });

    const event = storeEvent({
      roomId: room.id,
      senderId: user.id,
      type: packet.type,
      counter: packet.counter,
      payload: decryptedPayload
    });

    broadcastToRoom(room.name, {
      type: "server.event",
      event_id: event.id,
      room: room.name,
      sender: user.username,
      payload: decryptedPayload,
      created_at: event.created_at
    });
  });

  ws.on("close", () => {
    clients.delete(clientId);
  });
});

console.log(`Zero-trust chat server running on ws://0.0.0.0:${PORT}`);