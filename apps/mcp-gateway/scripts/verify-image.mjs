#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { validImageReference, verifyPackaging } from './verify-image/harness.mjs';
import { verifyStartup } from './verify-image/startup.mjs';

export async function main(args, boundary) {
  let code = 'INVALID_ARGUMENTS';
  try {
    if (args.length !== 4) throw new Error();
    const values = new Map();
    for (let index = 0; index < args.length; index += 2) {
      const flag = args[index];
      const value = args[index + 1];
      if (!['--image', '--suite'].includes(flag) || values.has(flag) ||
          typeof value !== 'string' || !value || value.length > 255 || /\s|[\x00-\x1f\x7f]/.test(value)) throw new Error();
      values.set(flag, value);
    }
    if (!validImageReference(values.get('--image'))) throw new Error();
    if (!['packaging', 'startup'].includes(values.get('--suite'))) { code = 'UNSUPPORTED_SUITE'; throw new Error(); }
    if (values.get('--suite') === 'startup') return await verifyStartup(values.get('--image'), boundary);
    return await verifyPackaging(values.get('--image'), boundary);
  } catch {
    return { type: 'image-packaging-verification', ok: false, code, readinessVerified: false };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = await main(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = report.ok ? 0 : ['INVALID_ARGUMENTS', 'UNSUPPORTED_SUITE'].includes(report.code) ? 2 : 1;
}
