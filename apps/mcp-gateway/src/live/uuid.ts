import { randomBytes } from "node:crypto";

export function createUuidV7(): string {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function timestampFromUuidV7(id: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    throw new TypeError("invalid UUIDv7");
  }
  const millis = Number.parseInt(`${id.slice(0, 8)}${id.slice(9, 13)}`, 16);
  const date = new Date(millis);
  if (!Number.isFinite(date.getTime())) {
    throw new TypeError("invalid UUIDv7 timestamp");
  }
  return `${date.toISOString().slice(0, -1)}000Z`;
}
