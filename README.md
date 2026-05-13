# verifypdf

Node.js CLI tool to inspect whether a PDF contains a digital signature, extract certificate information, and verify:

- signature integrity (tamper detection)
- certificate chain trust and validity
- signature timestamp metadata

## Usage

```bash
node index.js /absolute/or/relative/path/to/file.pdf
```

The command prints JSON with:

- `isSigned`: whether the PDF has signature data (`/ByteRange`)
- `signedByPfxCertificateLikely`: signature includes an X.509 certificate (common for PFX/PKCS#12 signing workflows)
- `signatures[].certificateInfo`: signer certificate subject/issuer/validity
- `signatures[].signatureVerification`: integrity + trust validation
- `signatures[].timestampVerification`: signing time metadata checks
- `signatures[].tamperCheck`: whether file coverage and signature integrity indicate tampering
