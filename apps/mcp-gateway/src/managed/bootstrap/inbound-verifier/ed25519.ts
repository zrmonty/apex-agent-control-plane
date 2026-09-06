// Public-point preflight only, never signing or signature verification. Node's
// createPublicKey accepts small-order/noncanonical Ed25519 encodings. Require a
// canonical, nonidentity point in the prime-order subgroup before native import.
// Curve decoding/addition: RFC8032 sections 5.1.1-5.1.4; L from section 5.1.
// https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.3
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (n: bigint) => (n % P + P) % P;
function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  for (; exponent; exponent >>= 1n, base = mod(base * base)) if (exponent & 1n) result = mod(result * base);
  return result;
}
const D = mod(-121665n * power(121666n, P - 2n));
const SQRT_MINUS_ONE = power(2n, (P - 1n) / 4n);
type Point = readonly [bigint, bigint, bigint, bigint]; // X, Y, Z, T
function add(p: Point, q: Point): Point {
  const a = mod((p[1] - p[0]) * (q[1] - q[0])), b = mod((p[1] + p[0]) * (q[1] + q[0]));
  const c = mod(2n * D * p[3] * q[3]), d = mod(2n * p[2] * q[2]);
  const e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
  return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
}
export function strongEd25519Point(bytes: Buffer): boolean {
  if (bytes.length !== 32) return false;
  let encoded = 0n;
  for (let i = 31; i >= 0; i--) encoded = (encoded << 8n) | BigInt(bytes[i]);
  const sign = encoded >> 255n, y = encoded & ((1n << 255n) - 1n);
  if (y >= P) return false;
  const yy = mod(y * y), denominator = mod(D * yy + 1n);
  if (denominator === 0n) return false;
  const xx = mod((yy - 1n) * power(denominator, P - 2n));
  let x = power(xx, (P + 3n) / 8n);
  if (mod(x * x) !== xx) x = mod(x * SQRT_MINUS_ONE);
  if (mod(x * x) !== xx || x === 0n && sign === 1n || x === 0n && y === 1n) return false;
  if ((x & 1n) !== sign) x = P - x;
  let point: Point = [x, y, 1n, mod(x * y)], product: Point = [0n, 1n, 1n, 0n];
  for (let scalar = L; scalar; scalar >>= 1n, point = add(point, point)) {
    if (scalar & 1n) product = add(product, point);
  }
  return product[2] !== 0n && product[0] === 0n && mod(product[1] - product[2]) === 0n;
}
