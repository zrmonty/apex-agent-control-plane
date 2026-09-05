import { createInterface } from "node:readline";

// Controlled test-only peer. EOF exits; it never creates another process.
const input = createInterface({ input: process.stdin });
process.stdout.write("ready\n");
input.on("line", line => process.stdout.write(line === "ping" ? "pong\n" : "unexpected\n"));
