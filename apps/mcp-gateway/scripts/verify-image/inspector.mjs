// Self-contained functions are sent as fixed Node module source, never mounted
// into or written inside the image. No certificates, clients, or RPCs are made.
export async function scanDist(root) {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const counts = { files: 0, bytes: 0, testArtifacts: 0, privateKeyFiles: 0 };
  let entries = 0;
  const require = (ok) => { if (!ok) throw new Error('PACKAGING_SCAN_FAILED'); };
  const testPath = /(?:^|\/)(?:__tests__|__fixtures__|tests?|fixtures?)(?:\/|$)|(?:^|[.\/_-])(?:test|spec|fixtures?)(?:[.\/_-]|$)/i;
  const privatePem = /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----/;
  function walk(directory, parts, depth) {
    require(depth <= 16);
    const metadata = fs.lstatSync(directory);
    require(metadata.isDirectory() && !metadata.isSymbolicLink());
    const opened = fs.opendirSync(directory, { bufferSize: 16 });
    try {
      for (let entry = opened.readSync(); entry !== null; entry = opened.readSync()) {
        require(++entries <= 4096);
        const file = path.join(directory, entry.name);
        const relative = [...parts, entry.name];
        const stat = fs.lstatSync(file);
        require(!stat.isSymbolicLink());
        if (testPath.test(relative.join('/'))) counts.testArtifacts++;
        if (stat.isDirectory()) { walk(file, relative, depth + 1); continue; }
        require(stat.isFile() && stat.size <= 2 * 1024 * 1024 &&
          counts.bytes + stat.size <= 32 * 1024 * 1024);
        const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
        try {
          const initial = fs.fstatSync(fd);
          require(initial.isFile() && initial.dev === stat.dev && initial.ino === stat.ino && initial.size === stat.size);
          const bytes = Buffer.alloc(stat.size + 1);
          let length = 0;
          while (length < bytes.length) {
            const read = fs.readSync(fd, bytes, length, bytes.length - length, null);
            if (read === 0) break;
            length += read;
          }
          require(length === stat.size && fs.fstatSync(fd).size === stat.size);
          counts.files++;
          counts.bytes += length;
          if (privatePem.test(bytes.subarray(0, length).toString('utf8'))) counts.privateKeyFiles++;
        } finally { fs.closeSync(fd); }
      }
    } finally { opened.closeSync(); }
  }
  try { walk(root, [], 0); } catch { throw new Error('PACKAGING_SCAN_FAILED'); }
  return counts;
}

export async function loadDescriptors(paths) {
  try {
    const { existsSync } = await import('node:fs');
    const { resolve, dirname } = await import('node:path');
    const { default: loader } = await import('@grpc/proto-loader');
    const { default: grpc } = await import('@grpc/grpc-js');
    if (paths.length !== 2 || !paths.every((file) => existsSync(file))) throw new Error();
    const definitions = paths.map((file) => loader.loadSync(file, {
      includeDirs: [resolve(dirname(file), '../..')],
      keepCase: true, longs: String, enums: String, defaults: false, oneofs: true,
    }));
    if (!definitions[0]['apex.v1.ProxyApproval'] || !definitions[1]['google.protobuf.Struct']) throw new Error();
    const loaded = definitions.map((definition) => grpc.loadPackageDefinition(definition));
    const services = [
      [loaded[0].apex.v1.GovernanceGateway, 'GovernanceGateway', ['Authorize', 'GetPolicy']],
      [loaded[0].apex.v1.ManagedProxyGovernance, 'ManagedProxyGovernance', ['AuthorizeManagedCall']],
      [loaded[1].apex.v1.EventIngest, 'EventIngest', ['Ingest']],
    ];
    for (const [constructor, name, methods] of services) {
      for (const method of methods) {
        const descriptor = constructor?.service?.[method];
        if (descriptor?.path !== `/apex.v1.${name}/${method}` ||
            typeof descriptor.requestSerialize !== 'function' ||
            typeof descriptor.responseDeserialize !== 'function') throw new Error();
      }
    }
    return { protoFiles: 2, descriptorServices: 3, rpcMethods: 4 };
  } catch { throw new Error('PACKAGING_IMPORT_FAILED'); }
}

async function inspectImage() {
  let counts = { files: 0, bytes: 0, testArtifacts: 0, privateKeyFiles: 0 };
  let descriptors = { protoFiles: 0, descriptorServices: 0, rpcMethods: 0 };
  let generatedSchemas = 0;
  let code = 'PACKAGING_SCAN_FAILED';
  try {
    if (process.getuid?.() !== 10001 || process.getgid?.() !== 10001) throw new Error();
    const { existsSync } = await import('node:fs');
    counts = await scanDist('/app/apps/mcp-gateway/dist');
    // Also bound the packaged proto tree before the real descriptor loader reads it.
    await scanDist('/app/contracts/proto');
    code = 'PACKAGING_IMPORT_FAILED';
    const live = await import('file:///app/apps/mcp-gateway/dist/live/grpc.js');
    const paths = [live.protoPath('governance.proto'), live.protoPath('event.proto')];
    if (paths[0] !== '/app/contracts/proto/apex/v1/governance.proto' ||
        paths[1] !== '/app/contracts/proto/apex/v1/event.proto' ||
        !existsSync(paths[0]) || !existsSync(paths[1])) throw new Error();
    descriptors = await loadDescriptors(paths);
    const generated = await import('@apex/contracts');
    for (const name of ['RuntimeConfiguration', 'McpProxySpec', 'ProxyApproval']) {
      if (generated[`${name}Schema`]?.typeName !== `apex.v1.${name}`) throw new Error();
      generatedSchemas++;
    }
    code = counts.testArtifacts === 0 && counts.privateKeyFiles === 0 && counts.files > 0
      ? 'PACKAGING_OK' : 'PACKAGING_ARTIFACTS_REJECTED';
  } catch { /* Static code and bounded counts only; never print an exception. */ }
  const ok = code === 'PACKAGING_OK';
  process.stdout.write(`${JSON.stringify({ type: 'image-packaging-inspection', ok, code,
    ...counts, ...descriptors, generatedSchemas })}\n`);
  process.exitCode = ok ? 0 : 1;
}

export function inspectorSource() {
  return `${scanDist.toString()}\n${loadDescriptors.toString()}\n(${inspectImage.toString()})();`;
}
