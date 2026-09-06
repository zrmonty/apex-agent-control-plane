import assert from "node:assert/strict";
import { test } from "node:test";
import { startLoad } from "./stage-reader/job.js";
import { FakeFiles, FakeTime } from "./stage-reader/fixture.js";

test("complete agent stage yields owned bytes only after physical close; dispose wipes", async () => {
  const fs = new FakeFiles();
  const load = startLoad({ expectedManifestSha256: "df4076b609d8e8b372883c1a906eddda3c9872de156ea8c45dfe01f5c50d4e63", toolSecretReferences: [], onFatal() {} },
    fs, new FakeTime(), {});
  const stage = await load.result;
  await load.closed;
  assert.equal(Object.keys(stage.files).length, 18);
  assert.equal(stage.files["instance-proof"].length, 32);
  assert.deepEqual(stage.files["runtime-revision.json"], Buffer.from("{}"));
  assert.equal(fs.paths.size, 0);
  assert.equal(fs.directoryClosed, 1);
  stage.dispose(); stage.dispose();
  for (const bytes of Object.values(stage.files)) assert(bytes.every(value => value === 0));
});
