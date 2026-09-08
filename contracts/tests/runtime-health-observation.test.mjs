import test from 'node:test';
import assert from 'node:assert/strict';
import { fromBinary, toBinary } from '@bufbuild/protobuf';
import { decodeStrict, encodeJson } from '../../packages/apex-contracts-ts/src/json.js';
import * as deployment from '../../packages/apex-contracts-ts/src/gen/apex/v1/proxy_runtime_deployment_pb.js';

test('fresh health observation carries nonce and shrinking lifetime separately from reconciliation', () => {
  const schema = deployment.RuntimeHealthObservationResponseSchema;
  assert.equal(schema?.typeName, 'apex.v1.RuntimeHealthObservationResponse');
  const input = { schemaVersion: 1, nonce: Buffer.alloc(32, 7).toString('base64'),
    sample: { schemaVersion: 1, report: { observedAtUnixUs: '9007199254740993' }, validForNs: '6999' } };
  const message = decodeStrict(schema, input);
  assert.deepEqual(encodeJson(schema, fromBinary(schema, toBinary(schema, message))), input);
  assert.equal(deployment.RuntimeHealthObservation.method.observe.input.typeName, 'apex.v1.RuntimeHealthObservationRequest');
  assert.throws(() => decodeStrict(deployment.RuntimeHealthObservationRequestSchema, { command: 'unsafe' }));
});
