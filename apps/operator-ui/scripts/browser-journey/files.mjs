import { closeSync, fstatSync, lstatSync, openSync, opendirSync, readSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { requireValue } from './policy.mjs';

export function readBounded(filename, limit) {
  requireValue(!lstatSync(filename).isSymbolicLink(), 'configuration');
  const fd = openSync(filename, 'r');
  try {
    const stat = fstatSync(fd);
    requireValue(stat.isFile() && stat.size > 0 && stat.size <= limit, 'configuration');
    const bytes = Buffer.alloc(stat.size + 1); let read = 0;
    while (read < bytes.length) {
      const count = readSync(fd, bytes, read, bytes.length - read, null);
      if (!count) break;
      read += count;
    }
    requireValue(read === stat.size, 'configuration');
    return bytes.subarray(0, read);
  } finally { closeSync(fd); }
}
export function loadAssets(dist) {
  const root = realpathSync(dist); const assets = new Map(); let total = 0;
  const add = (name, type) => {
    const file = path.join(root, name);
    requireValue(realpathSync(file).startsWith(root + path.sep), 'configuration');
    const body = readBounded(file, 8 * 1024 * 1024); total += body.length;
    requireValue(total <= 32 * 1024 * 1024, 'configuration');
    assets.set('/' + name.replaceAll(path.sep, '/'), { body, type });
  };
  add('index.html', 'text/html; charset=utf-8');
  const directory = path.join(root, 'assets');
  requireValue(!lstatSync(directory).isSymbolicLink() && realpathSync(directory) === directory, 'configuration');
  const handle = opendirSync(directory); let count = 0;
  const types = { '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
    '.woff2': 'font/woff2', '.woff': 'font/woff', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
  try {
    for (let entry; (entry = handle.readSync());) {
      requireValue(++count <= 256 && entry.isFile() && !entry.isSymbolicLink(), 'configuration');
      const type = types[path.extname(entry.name)];
      if (type) add(path.join('assets', entry.name), type);
    }
  } finally { handle.closeSync(); }
  return assets;
}
export function labCredentials(realm) {
  requireValue(Array.isArray(realm?.users), 'configuration');
  const users = realm.users.filter(user => user.enabled === true && typeof user.username === 'string'
    && !user.username.startsWith('service-account-') && user.credentials?.some(value => value.type === 'password'));
  requireValue(users.length === 1, 'configuration');
  const passwords = users[0].credentials.filter(value => value.type === 'password');
  requireValue(passwords.length === 1 && passwords[0].temporary === false
    && typeof passwords[0].value === 'string' && passwords[0].value.length > 0 && passwords[0].value.length <= 1024
    && users[0].username.length > 0 && users[0].username.length <= 128, 'configuration');
  return { username: users[0].username, password: passwords[0].value };
}
