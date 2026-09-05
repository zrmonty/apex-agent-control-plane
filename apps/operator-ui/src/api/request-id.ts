/** One new ID per user mutation; retain the same value for an uncertain retry. */
export function newRequestId(): string {
  const millis = Date.now();
  if (!Number.isSafeInteger(millis) || millis < 0 || millis >= 2 ** 48) {
    throw new RangeError("The clock cannot produce a valid request identifier.");
  }
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let epoch = BigInt(millis);
  for (let index = 5; index >= 0; index--) {
    bytes[index] = Number(epoch & 255n);
    epoch >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
