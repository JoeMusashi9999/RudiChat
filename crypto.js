import sodium from "libsodium-wrappers";

await sodium.ready;

export function toBase64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

export function fromBase64(str) {
  return sodium.from_base64(str, sodium.base64_variants.ORIGINAL);
}

export function generateIdentityKeypair() {
  const keys = sodium.crypto_sign_keypair();

  return {
    publicKey: toBase64(keys.publicKey),
    privateKey: toBase64(keys.privateKey)
  };
}

export function signMessage(privateKeyBase64, messageString) {
  const privateKey = fromBase64(privateKeyBase64);
  const message = sodium.from_string(messageString);

  const signature = sodium.crypto_sign_detached(message, privateKey);

  return toBase64(signature);
}

export function verifySignature(publicKeyBase64, messageString, signatureBase64) {
  const publicKey = fromBase64(publicKeyBase64);
  const signature = fromBase64(signatureBase64);
  const message = sodium.from_string(messageString);

  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

export function generateSymmetricKey() {
  return toBase64(sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES));
}

export function encryptPayload(keyBase64, payloadObject, aadObject = {}) {
  const key = fromBase64(keyBase64);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  const plaintext = sodium.from_string(JSON.stringify(payloadObject));
  const aad = sodium.from_string(JSON.stringify(aadObject));

  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad,
    null,
    nonce,
    key
  );

  return {
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext)
  };
}

export function decryptPayload(keyBase64, encryptedPayload, aadObject = {}) {
  const key = fromBase64(keyBase64);
  const nonce = fromBase64(encryptedPayload.nonce);
  const ciphertext = fromBase64(encryptedPayload.ciphertext);
  const aad = sodium.from_string(JSON.stringify(aadObject));

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    aad,
    nonce,
    key
  );

  return JSON.parse(sodium.to_string(plaintext));
}

export function canonicalizePacketForSigning(packet) {
  return JSON.stringify({
    version: packet.version,
    type: packet.type,
    sender: packet.sender,
    room: packet.room,
    counter: packet.counter,
    nonce: packet.nonce,
    ciphertext: packet.ciphertext
  });
}