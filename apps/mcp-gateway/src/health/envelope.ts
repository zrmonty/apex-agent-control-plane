/** Byte-bounded raw envelope capture. Node remains the strict HTTP parser.
 * Preserve wire whitespace which IncomingMessage.rawHeaders has already trimmed.
 * Never retain incoming chunks or allocate in proportion to an oversized chunk. */
export class HeaderCapture {
  private readonly storage = Buffer.alloc(4097);
  private used = 0;
  complete = false;
  invalid = false;
  bodyBytes = 0;
  fields = new Map<string, string>();
  accept(chunk: Buffer): void {
    if (this.invalid) return;
    if (this.complete) { this.bodyBytes += chunk.length; return; }
    const kept = Math.min(chunk.length, this.storage.length - this.used);
    chunk.copy(this.storage, this.used, 0, kept); this.used += kept;
    const end = this.storage.subarray(0, this.used).indexOf("\r\n\r\n");
    if (end < 0) { if (this.used > 4096) this.invalid = true; return; }
    const size = end + 4;
    if (size > 4096) { this.invalid = true; return; }
    this.complete = true;
    this.bodyBytes = this.used - size + chunk.length - kept;
    const lines = this.storage.subarray(0, end).toString("latin1").split("\r\n");
    if (lines.length - 1 > 32) { this.invalid = true; this.storage.fill(0); return; }
    for (const line of lines.slice(1)) {
      const colon = line.indexOf(":"), name = line.slice(0, colon).toLowerCase();
      if (colon < 1 || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || this.fields.has(name)) { this.invalid = true; break; }
      const value = line.slice(colon + 1);
      this.fields.set(name, value.startsWith(" ") ? value.slice(1) : value);
    }
    this.storage.fill(0);
  }
  clear(): void { this.storage.fill(0); this.fields.clear(); }
}

export function uniqueHeaders(raw: readonly string[]): boolean {
  if (raw.length > 64 || raw.length % 2 !== 0) return false;
  const names = new Set<string>();
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i].toLowerCase();
    if (names.has(name)) return false;
    names.add(name);
  }
  return true;
}
