import { lstat, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";

import { GatewayError } from "../contracts.js";
import type { LiveGrpcConfig } from "./config.js";

const MAX_SECRET_BYTES = 1024 * 1024;
const MAX_TOKEN_BYTES = 4096;

export type ClientMaterial = {
  readonly ca: Buffer;
  readonly clientCert: Buffer;
  readonly clientKey: Buffer;
  readonly token: string;
};

export async function loadClientMaterial(
  config: LiveGrpcConfig,
  trustedSecretBase: string,
): Promise<ClientMaterial> {
  const base = await realpath(trustedSecretBase).catch(() => {
    throw unavailable();
  });
  const caPath = await trustedPath(config.caFile, base, false);
  const certPath = await trustedPath(config.clientCertFile, base, false);
  const keyPath = await trustedPath(config.clientKeyFile, base, true);
  const tokenPath = await trustedPath(config.tokenFile, base, true);
  const [ca, clientCert, clientKey, tokenBytes] = await Promise.all([
    boundedRead(caPath, MAX_SECRET_BYTES),
    boundedRead(certPath, MAX_SECRET_BYTES),
    boundedRead(keyPath, MAX_SECRET_BYTES),
    boundedRead(tokenPath, MAX_TOKEN_BYTES),
  ]);
  let tokenText: string;
  try {
    tokenText = new TextDecoder("utf-8", { fatal: true }).decode(tokenBytes);
  } catch {
    throw unavailable();
  }
  const token = tokenText.endsWith("\n") ? tokenText.slice(0, -1) : tokenText;
  if (token.length === 0 || (tokenText !== token && tokenText !== `${token}\n`)) {
    throw unavailable();
  }
  if (token.length < 16 || token.length > MAX_TOKEN_BYTES || /\s/.test(token)) {
    throw unavailable();
  }
  return { ca, clientCert, clientKey, token };
}

async function trustedPath(
  configured: string,
  base: string,
  privateMaterial: boolean,
): Promise<string> {
  const candidate = path.resolve(configured);
  const info = await lstat(candidate).catch(() => {
    throw unavailable();
  });
  if (!info.isFile() || info.isSymbolicLink()) {
    throw unavailable();
  }
  const canonical = await realpath(candidate).catch(() => {
    throw unavailable();
  });
  if (canonical !== base && !canonical.startsWith(`${base}${path.sep}`)) {
    throw unavailable();
  }
  const metadata = await stat(canonical).catch(() => {
    throw unavailable();
  });
  if (!metadata.isFile() || metadata.size === 0 || metadata.size > MAX_SECRET_BYTES) {
    throw unavailable();
  }
  if (privateMaterial && process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw unavailable();
  }
  return canonical;
}

async function boundedRead(file: string, maxBytes: number): Promise<Buffer> {
  const contents = await readFile(file).catch(() => {
    throw unavailable();
  });
  if (contents.length === 0 || contents.length > maxBytes) {
    throw unavailable();
  }
  return contents;
}

function unavailable(): GatewayError {
  return new GatewayError("GOVERNANCE_UNAVAILABLE", "request rejected safely");
}
