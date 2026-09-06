import { isIP } from "node:net";
import { address } from "../runtime-config/network.js";

export const relayRefused = () => new Error("guard relay refused safely");
export const CONNECT_ACK = Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n");
export const HANDSHAKE_NS = 10_000_000_000n;

/** Explicit numeric addresses only; no wildcard, zone, mapped-family or DNS bind. */
export function numericAddress(value: unknown): string {
  try {
    if (typeof value !== "string" || value.length > 64 || value.includes("%") || !isIP(value)) throw relayRefused();
    const ip = address(value);
    if (ip.start === 0n || (ip.width === 128 && ip.start >> 32n === 0xffffn)) throw relayRefused();
    return ip.width === 32 ? value : new URL(`https://[${value}]/`).hostname.slice(1, -1);
  } catch { throw relayRefused(); }
}
export function relayPort(value: unknown, ephemeral = false): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < (ephemeral ? 0 : 1) || value > 65535) throw relayRefused();
  return value;
}

/** Undefined means bounded incomplete handshake, not permission to resolve. */
export function parseConnect(bytes: Buffer): Readonly<{ host: string; port: number }> | undefined {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length > 2048) throw relayRefused();
    for (const byte of bytes) if ((byte < 32 && byte !== 13 && byte !== 10) || byte > 126) throw relayRefused();
    const end = bytes.indexOf("\r\n\r\n");
    if (end < 0) { if (bytes.length === 2048) throw relayRefused(); return undefined; }
    if (end + 4 !== bytes.length) throw relayRefused(); // no early TLS, body or second request
    const matched = /^CONNECT ([^\s]+) HTTP\/1\.1\r\n[Hh][Oo][Ss][Tt]: \1\r\n\r\n$/.exec(bytes.toString("ascii"));
    if (!matched) throw relayRefused();
    const authority = matched[1], colon = authority.lastIndexOf(":"), host = authority.slice(0, colon), rawPort = authority.slice(colon + 1);
    if (colon < 1 || host.length > 512 || !/^[1-9][0-9]{0,4}$/.test(rawPort) ||
      !/^(?:[a-z0-9.-]+|\[[a-f0-9:]+\])$/.test(host)) throw relayRefused();
    const port = relayPort(Number(rawPort));
    if (new URL(`https://${authority}/`).hostname !== host) throw relayRefused();
    return Object.freeze({ host, port });
  } catch { throw relayRefused(); }
}
