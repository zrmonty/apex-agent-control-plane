import assert from "node:assert/strict";
import test from "node:test";

import { createGrpcClient, protoPath } from "./grpc.js";
import type { ClientMaterial } from "./secrets.js";

// Self-signed, test-only identity. Clients are closed without making any RPCs.
const certificate = Buffer.from(`-----BEGIN CERTIFICATE-----
MIIBLjCB1KADAgECAghVfoafntsEIDAKBggqhkjOPQQDAjAdMRswGQYDVQQDExJn
cnBjLWNvbnRyYWN0LXRlc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAw
WjAdMRswGQYDVQQDExJncnBjLWNvbnRyYWN0LXRlc3QwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASwzntIN9bnFuIjrOPrFxGq+ix50PEKolDlqSPf67WIFxrVuEUW
Pro7BMLbdUdclun6WCdssIsUw9E3a8L1ffK6MAoGCCqGSM49BAMCA0kAMEYCIQDe
+saC+quaJt1k9UJXft8jizRu/jpbdjtbqanR1ayKiwIhAL6jlyivmqcRo0/FiA4/
RgHZuxc/cRt4ABehFPbh4nmi
-----END CERTIFICATE-----`);
const material: ClientMaterial = {
  ca: certificate,
  clientCert: certificate,
  clientKey: Buffer.from(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS95Xqq5ZmQ8mHoaQ
v9qcRkLRHU4FvoeO75NKzDTE1FmhRANCAASwzntIN9bnFuIjrOPrFxGq+ix50PEK
olDlqSPf67WIFxrVuEUWPro7BMLbdUdclun6WCdssIsUw9E3a8L1ffK6
-----END PRIVATE KEY-----`),
  token: "unused-contract-test-token",
};

test("loads the real governance contract with root-relative approval imports", (t) => {
  const client = createGrpcClient(
    protoPath("governance.proto"), "GovernanceGateway", "https://localhost:9443/", material,
  );
  t.after(() => client.close());

  assert.equal(typeof client.authorize, "function");
  assert.equal(typeof client.getPolicy, "function");
});

test("still loads the real event contract with its well-known protobuf import", (t) => {
  const client = createGrpcClient(
    protoPath("event.proto"), "EventIngest", "https://localhost:9443/", material,
  );
  t.after(() => client.close());

  assert.equal(typeof client.ingest, "function");
});
