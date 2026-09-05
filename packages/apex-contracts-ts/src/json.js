import { fromJson, toJson, ScalarType } from "@bufbuild/protobuf";
import { parseUniqueJson } from "./duplicate-json.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTEGER64 = new Set([ScalarType.INT64, ScalarType.UINT64, ScalarType.FIXED64, ScalarType.SFIXED64, ScalarType.SINT64]);
const UNSIGNED64 = new Set([ScalarType.UINT64, ScalarType.FIXED64]);
const MAX_BYTES = 256 * 1024;
const MAX_FIELDS = 8192;
const MAX_DEPTH = 64;

// This is the stricter Apex profile of ProtoJSON. It deliberately rejects
// numeric uint64 input even when the general Protobuf parser would accept it.
export function decodeStrict(schema, input) {
  if (typeof input === "string" && new TextEncoder().encode(input).length > MAX_BYTES) throw new Error("JSON size limit exceeded");
  const value = typeof input === "string" ? parseUniqueJson(input, { maxDepth: MAX_DEPTH, maxFields: MAX_FIELDS }) : input;
  boundJson(value);
  const encoded = JSON.stringify(value);
  if (encoded === undefined || new TextEncoder().encode(encoded).length > MAX_BYTES) throw new Error("JSON size limit exceeded");
  checkMessage(schema, value);
  const message = fromJson(schema, value, { ignoreUnknownFields: false });
  validateSemantics(schema, message);
  return message;
}
export function encodeJson(schema, message) {
  const result = toJson(schema, message);
  // Apply the same bounds and validation to responses and generated configs.
  decodeStrict(schema, result);
  return result;
}
function boundJson(value) {
  let fields = 0;
  const visit = (node, depth) => {
    if (depth > MAX_DEPTH) throw new Error("JSON depth limit exceeded");
    if (node && typeof node === "object") {
      for (const [key, entry] of Object.entries(node)) {
        if (++fields > MAX_FIELDS) throw new Error("JSON field count limit exceeded");
        if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("unsafe JSON field");
        visit(entry, depth + 1);
      }
    }
  };
  visit(value, 0);
}
function checkMessage(schema, value) {
  if (schema.typeName.startsWith("google.protobuf.")) return;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("expected message object");
  const names = new Map(schema.fields.flatMap(field => [[field.jsonName, field], [field.name, field]]));
  const seen = new Set();
  for (const [key, entry] of Object.entries(value)) {
    const field = names.get(key);
    if (!field) throw new Error("unknown field: " + key);
    if (seen.has(field.number)) throw new Error("duplicate field: " + key);
    seen.add(field.number);
    const items = field.fieldKind === "list" && Array.isArray(entry) ? entry
      : field.fieldKind === "map" && entry && typeof entry === "object" ? Object.values(entry) : [entry];
    for (const item of items) {
      if (INTEGER64.has(field.scalar)) {
        const unsigned = UNSIGNED64.has(field.scalar);
        if (typeof item !== "string" || !(unsigned ? /^(0|[1-9][0-9]*)$/ : /^(0|-?[1-9][0-9]*)$/).test(item)) {
          throw new Error(field.jsonName + " requires a decimal integer string");
        }
        const integer = BigInt(item);
        if (integer < (unsigned ? 0n : -(1n << 63n)) || integer > (unsigned ? (1n << 64n) - 1n : (1n << 63n) - 1n)) {
          throw new Error(field.jsonName + " is outside 64-bit range");
        }
      } else if (field.message && item !== null) {
        checkMessage(field.message, item);
      } else if (field.enum && item !== null) {
        const found = field.enum.values.find(v => v.name === item || v.number === item);
        if (!found) throw new Error("unknown enum value");
      }
    }
  }
}
function validateSemantics(schema, message) {
  // protobuf-es represents well-known JSON types directly as JSON values.
  if (schema.typeName.startsWith("google.protobuf.")) return;
  for (const field of schema.fields) {
    const oneof = field.oneof ? message[field.oneof.localName] : undefined;
    if (field.oneof && oneof?.case !== field.localName) continue;
    const value = field.oneof ? oneof.value : message[field.localName];
    if (field.name === "request_id" && !UUID_V7.test(value)) throw new Error("requestId must be lowercase UUIDv7");
    if (field.name === "approval_mode" && field.scalar === ScalarType.STRING) approvalMode(value);
    if (field.message) {
      const values = field.fieldKind === "list" ? value : field.fieldKind === "map" ? Object.values(value) : [value];
      for (const nested of values) if (nested) validateSemantics(field.message, nested);
    }
  }
  if (schema.typeName === "apex.v1.RuntimeConfiguration") {
    if (message.schemaVersion !== 1) throw new Error("unsupported runtime schema version");
    let url;
    try { url = new URL(message.resourceUrl); } catch { throw new Error("resource URL required"); }
    if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) throw new Error("invalid HTTPS resource URL");
    if (message.auth?.audience !== message.resourceUrl) throw new Error("audience must equal the resource URL");
    if (!message.spec?.ingress || !message.telemetry || message.generation === 0n) throw new Error("missing runtime configuration");
  }
}
export function approvalMode(value) {
  if (!["none", "operator", "dual-operator"].includes(value)) throw new Error("unknown approval mode");
  return value;
}
export function requireCapabilities(capabilities, required) {
  if (!Array.isArray(capabilities?.supported) || required.some(name => !capabilities.supported.includes(name))) {
    throw new Error("required server capability unavailable");
  }
}
