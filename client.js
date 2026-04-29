import WebSocket from "ws";
import readline from "readline";
import fs from "fs";

import {
    generateIdentityKeypair,
    signMessage,
    encryptPayload,
    canonicalizePacketForSigning
} from "./crypto.js";

const SERVER_URL = process.env.SERVER_URL || "ws://localhost:8080";
const CHAT_TEST_KEY = process.env.CHAT_TEST_KEY;

if (!CHAT_TEST_KEY) {
    console.error("Missing CHAT_TEST_KEY environment variable.");
    process.exit(1);
}

const KEY_FILE = "client-keys.json";

function loadOrCreateKeys() {
    if (fs.existsSync(KEY_FILE)) {
        return JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
    }

    const keys = generateIdentityKeypair();
    fs.writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2));
    return keys;
}

const keys = loadOrCreateKeys();

const username = process.argv[2] || "derek";
const room = process.argv[3] || "general";

let counter = 1;

const ws = new WebSocket(SERVER_URL);

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function sendChatMessage(message) {
    const aad = {
        version: 1,
        type: "chat.message",
        sender: username,
        room,
        counter
    };

    const encrypted = encryptPayload(
        CHAT_TEST_KEY,
        {
            message,
            sent_at: Date.now()
        },
        aad
    );

    const packet = {
        ...aad,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext
    };

    const signedData = canonicalizePacketForSigning(packet);
    const signature = signMessage(keys.privateKey, signedData);

    ws.send(JSON.stringify({
        ...packet,
        signature
    }));

    counter++;
}

function promptLoop() {
    rl.question("> ", (input) => {
        if (input.trim() === "/quit") {
            ws.close();
            rl.close();
            return;
        }

        if (input.trim().length > 0) {
            sendChatMessage(input.trim());
        }

        promptLoop();
    });
}

ws.on("open", () => {
  console.log(`Connected to ${SERVER_URL}`);
  console.log(`User: ${username}`);
  console.log(`Room: ${room}`);
  console.log(`Public key: ${keys.publicKey}`);
  console.log("Type /quit to exit.");

  ws.send(JSON.stringify({
    version: 1,
    type: "user.register",
    username,
    public_key: keys.publicKey
  }));

  promptLoop();
});

ws.on("message", (raw) => {
    const packet = JSON.parse(raw.toString());

    if (packet.type === "server.event") {
        console.log(`\n[${packet.room}] ${packet.sender}: ${packet.payload.message}`);
        process.stdout.write("> ");
        return;
    }

    if (packet.type === "server.history") {
        console.log(`\n--- recent history for ${packet.room} ---`);
        for (const event of packet.events) {
            console.log(`[${packet.room}] ${event.sender}: ${event.payload.message}`);
        }
        console.log("--- end history ---");
        process.stdout.write("> ");
        return;
    }

    if (packet.type === "error") {
        console.log(`\nServer error: ${packet.error}`);
        process.stdout.write("> ");
        return;
    }

    console.log("\nServer:", packet);
    process.stdout.write("> ");
});

ws.on("close", () => {
    console.log("\nDisconnected.");
    rl.close();
});

ws.on("error", (err) => {
    console.error("WebSocket error:", err.message);
});