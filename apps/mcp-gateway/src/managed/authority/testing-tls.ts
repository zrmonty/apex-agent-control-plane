// Public, self-signed TEST ONLY identity; never a production credential or trust root.
// Its original DNS name is grpc-contract-test. Valid 2026-2036, no external services.
export const certificate = Buffer.from(`-----BEGIN CERTIFICATE-----
MIIBLjCB1KADAgECAghVfoafntsEIDAKBggqhkjOPQQDAjAdMRswGQYDVQQDExJn
cnBjLWNvbnRyYWN0LXRlc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAw
WjAdMRswGQYDVQQDExJncnBjLWNvbnRyYWN0LXRlc3QwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAASwzntIN9bnFuIjrOPrFxGq+ix50PEKolDlqSPf67WIFxrVuEUW
Pro7BMLbdUdclun6WCdssIsUw9E3a8L1ffK6MAoGCCqGSM49BAMCA0kAMEYCIQDe
+saC+quaJt1k9UJXft8jizRu/jpbdjtbqanR1ayKiwIhAL6jlyivmqcRo0/FiA4/
RgHZuxc/cRt4ABehFPbh4nmi
-----END CERTIFICATE-----`);
export const key = Buffer.from(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgS95Xqq5ZmQ8mHoaQ
v9qcRkLRHU4FvoeO75NKzDTE1FmhRANCAASwzntIN9bnFuIjrOPrFxGq+ix50PEK
olDlqSPf67WIFxrVuEUWPro7BMLbdUdclun6WCdssIsUw9E3a8L1ffK6
-----END PRIVATE KEY-----`);
