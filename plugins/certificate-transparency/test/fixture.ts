// A self-signed certificate made for these tests (openssl req -x509), with
// the SANs DNS:www.example.test, DNS:example.test, IP:192.0.2.1,
// DNS:shop.other-brand.test and email:admin@example.test. Its key was
// thrown away.
export const testPEM = `-----BEGIN CERTIFICATE-----
MIIB5jCCAYygAwIBAgIUFO4gpGSdvoasRXT5mDOkY9Kdz+0wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQd3d3LmV4YW1wbGUudGVzdDAeFw0yNjEwMTYxNzU5NDJaFw0y
NjEwMTcxNzU5NDJaMBsxGTAXBgNVBAMMEHd3dy5leGFtcGxlLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS2A/hLjMAvtG9H1BIGajIGtAPQRFMIX2QhAtOr
URFbDXoQDFRCgKNCANNfVV2gvIu6wtD/nahHk68/CvKPiP6Po4GtMIGqMB0GA1Ud
DgQWBBSnRReszTrHlrWK9eUjkoWAikLPYDAfBgNVHSMEGDAWgBSnRReszTrHlrWK
9eUjkoWAikLPYDBaBgNVHREEUzBRghB3d3cuZXhhbXBsZS50ZXN0ggxleGFtcGxl
LnRlc3SHBMAAAgGCFXNob3Aub3RoZXItYnJhbmQudGVzdIESYWRtaW5AZXhhbXBs
ZS50ZXN0MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIgDr8wIhYN4opg
Yb3qP7AeV6aDqeTrsciAwcP3HwrifRcCIQDvoGNHmFMyGDs+sqA4XzLhDWVBWpRu
2mSSSrdMWl6w9A==
-----END CERTIFICATE-----
`;
