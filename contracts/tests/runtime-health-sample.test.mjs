import test from 'node:test';
import assert from 'node:assert/strict';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { decodeStrict, encodeJson } from '../../packages/apex-contracts-ts/src/json.js';
import * as runtime from '../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_runtime_pb.js';

test('health sample transports remaining duration separately from original report timestamps', () => {
  const schema = runtime.RuntimeHealthSampleSchema;
  assert.equal(schema?.typeName, 'apex.v1.RuntimeHealthSample');
  const input = { schemaVersion: 1, report: { observedAtUnixUs: '9007199254740993',
    stages: [{ name: 'readiness.network', durationNs: '7000', durationUs: '7' }] }, validForNs: '6999' };
  const message = decodeStrict(schema, input);
  assert.equal(message.validForNs, 6999n);
  assert.deepEqual(encodeJson(schema, fromBinary(schema, toBinary(schema, message))), input);
  assert.equal(message.report.observedAtUnixUs, 9007199254740993n);
  assert.throws(() => decodeStrict(schema, { ...input, arbitraryCommand: 'unsafe' }));
});
