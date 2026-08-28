import { createHash, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function generateEncryptionKey(): string {
  return randomBytes(32).toString("base64url");
}

export function encryptText(plain: string, keyB64?: string): { key: string; ciphertext: string } {
  const key = keyB64 ? Buffer.from(keyB64, "base64url") : randomBytes(32);
  if (key.length !== 32) {
    throw new Error("Encryption key must decode to 32 bytes");
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  const packed = Buffer.concat([iv, tag, encrypted]).toString("base64");
  return { key: key.toString("base64url"), ciphertext: packed };
}

export function decryptText(ciphertext: string, keyB64: string): string {
  const key = Buffer.from(keyB64, "base64url");
  if (key.length !== 32) {
    throw new Error("Encryption key must decode to 32 bytes");
  }
  const packed = Buffer.from(ciphertext, "base64");
  if (packed.length < 29) {
    throw new Error("Ciphertext is too short");
  }
  const iv = packed.subarray(0, 12);
  const tag = packed.subarray(12, 28);
  const encrypted = packed.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}
