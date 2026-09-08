import { CancelledNotificationSchema } from "@modelcontextprotocol/sdk/types.js";

/** Only a validated, id-less cancellation notification may use control capacity. */
export function cancellation(body: unknown) {
  const parsed = CancelledNotificationSchema.safeParse(body);
  if (!parsed.success || !body || Object.hasOwn(body, "id")) return undefined;
  const id = parsed.data.params?.requestId;
  if (typeof id === "number" ? Number.isSafeInteger(id) : typeof id === "string" && id.length > 0 && id.length <= 128) {
    return parsed.data;
  }
  return undefined;
}
