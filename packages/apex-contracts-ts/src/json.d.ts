import type { DescMessage, JsonValue, MessageShape } from "@bufbuild/protobuf";

export function decodeStrict<T extends DescMessage>(schema: T, input: JsonValue | string): MessageShape<T>;
export function encodeJson<T extends DescMessage>(schema: T, message: MessageShape<T>): JsonValue;
export function approvalMode(value: unknown): "none" | "operator" | "dual-operator";
export function requireCapabilities(capabilities: { supported: string[] } | undefined, required: readonly string[]): void;
