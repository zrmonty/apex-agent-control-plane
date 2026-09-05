// Controlled subprocess fixture only; never imported by the production graph.
const mode: string | undefined = process.argv[2];
if (mode === "identity") {
  process.stdout.write(JSON.stringify({ pid: process.pid, parent: process.ppid }));
} else if (mode === "hang" || mode === "ignore-term" || mode === "soft-exit") {
  if (mode === "ignore-term") process.on("SIGTERM", () => {});
  if (mode === "soft-exit") process.on("SIGTERM", () => process.exit(0));
  process.stdout.write("ready");
  // Finite safety fuse also contains a broken runner during RED verification.
  setTimeout(() => process.exit(0), 3000);
  setInterval(() => {}, 100);
} else if (mode === "stdout-flood" || mode === "stderr-flood") {
  setTimeout(() => process.exit(0), 1000); // RED safety fuse; a fixed-size chunk avoids child-side unbounded allocation.
  const stream = mode === "stdout-flood" ? process.stdout : process.stderr;
  const chunk = Buffer.alloc(4096, 0x78);
  const pump = () => {
    if (stream.write(chunk)) setTimeout(pump, 1);
    else stream.once("drain", () => setTimeout(pump, 1));
  };
  pump();
} else if (mode === "exact-utf8") {
  process.stdout.write("€".repeat(5461) + "x"); // 16384 bytes, not characters.
  process.stderr.write("é".repeat(8192));
} else if (mode === "overflow-on-exit") {
  process.stdout.write("€".repeat(5462)); // 16386 bytes; normal exit must still fail.
} else {
  throw new Error("unknown controlled child mode");
}
