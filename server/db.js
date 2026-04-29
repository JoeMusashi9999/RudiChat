import Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";

export const db = new Database("chat.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  public_key TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
  room_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  joined_at INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id),
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  room_id TEXT NOT NULL,
  sender_id TEXT NOT NULL,
  type TEXT NOT NULL,
  counter INTEGER NOT NULL,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (room_id) REFERENCES rooms(id),
  FOREIGN KEY (sender_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_counters (
  user_id TEXT PRIMARY KEY,
  last_counter INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

export function getOrCreateUser(username, publicKey = null) {
  let user = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  ).get(username);

  if (user) return user;

  const newUser = {
    id: uuidv4(),
    username,
    public_key: publicKey,
    created_at: Date.now()
  };

  db.prepare(`
    INSERT INTO users (id, username, public_key, created_at)
    VALUES (@id, @username, @public_key, @created_at)
  `).run(newUser);

  return newUser;
}

export function getOrCreateRoom(name) {
  let room = db.prepare(
    "SELECT * FROM rooms WHERE name = ?"
  ).get(name);

  if (room) return room;

  const newRoom = {
    id: uuidv4(),
    name,
    created_at: Date.now()
  };

  db.prepare(`
    INSERT INTO rooms (id, name, created_at)
    VALUES (@id, @name, @created_at)
  `).run(newRoom);

  return newRoom;
}

export function addUserToRoom(userId, roomId, role = "member") {
  db.prepare(`
    INSERT OR IGNORE INTO room_members (room_id, user_id, role, joined_at)
    VALUES (?, ?, ?, ?)
  `).run(roomId, userId, role, Date.now());
}

export function checkReplay(userId, counter) {
  const row = db.prepare(`
    SELECT last_counter FROM user_counters WHERE user_id = ?
  `).get(userId);

  if (row && counter <= row.last_counter) {
    return false;
  }

  db.prepare(`
    INSERT INTO user_counters (user_id, last_counter)
    VALUES (?, ?)
    ON CONFLICT(user_id)
    DO UPDATE SET last_counter = excluded.last_counter
  `).run(userId, counter);

  return true;
}

export function storeEvent({ roomId, senderId, type, counter, payload }) {
  const event = {
    id: uuidv4(),
    room_id: roomId,
    sender_id: senderId,
    type,
    counter,
    payload: JSON.stringify(payload),
    created_at: Date.now()
  };

  db.prepare(`
    INSERT INTO events (
      id, room_id, sender_id, type, counter, payload, created_at
    )
    VALUES (
      @id, @room_id, @sender_id, @type, @counter, @payload, @created_at
    )
  `).run(event);

  return event;
}

export function getRecentRoomEvents(roomId, limit = 50) {
  return db.prepare(`
    SELECT
      events.id,
      events.type,
      events.counter,
      events.payload,
      events.created_at,
      users.username AS sender
    FROM events
    JOIN users ON users.id = events.sender_id
    WHERE events.room_id = ?
    ORDER BY events.created_at DESC
    LIMIT ?
  `).all(roomId, limit).reverse();
}

export function registerUserPublicKey(username, publicKey) {
  const existing = db.prepare(`
    SELECT * FROM users WHERE username = ?
  `).get(username);

  if (existing && existing.public_key) {
    return {
      ok: false,
      error: "User already has a public key registered"
    };
  }

  const user = getOrCreateUser(username, publicKey);

  db.prepare(`
    UPDATE users
    SET public_key = ?
    WHERE id = ?
  `).run(publicKey, user.id);

  return {
    ok: true,
    user
  };
}