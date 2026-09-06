import assert from 'node:assert/strict';
import test from 'node:test';
import { create, toJson } from '@bufbuild/protobuf';
import * as c from '../../packages/apex-contracts-ts/src/index.js';

test('each lifecycle response carries its durable acceptance and exact large generation', () => {
  for (const name of ['DeployProxy', 'ResumeProxy', 'PauseProxy', 'RetireProxy', 'RotateProxyCredentials', 'RollbackProxy']) {
    const schema = c[`${name}ResponseSchema`];
    const response = create(schema, { operation: create(c.ProxyOperationSchema, {
      operationId: '0191b7f1-7f2c-7c13-9a61-2f29f2be1003', generation: 9007199254740993n,
    }) });
    assert.equal(toJson(schema, response).operation?.generation, '9007199254740993', name);
  }
});
