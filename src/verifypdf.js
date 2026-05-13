const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const MAX_DER_LENGTH_BYTES = 4;
const CONTENTS_SEARCH_WINDOW_BYTES = 8192;

function parseDerLength(buffer) {
  if (!buffer || buffer.length < 2 || buffer[0] !== 0x30) {
    return null;
  }

  const firstLengthByte = buffer[1];
  if ((firstLengthByte & 0x80) === 0) {
    return 2 + firstLengthByte;
  }

  const lengthBytesCount = firstLengthByte & 0x7f;
  if (
    lengthBytesCount === 0 ||
    2 + lengthBytesCount > buffer.length ||
    lengthBytesCount > MAX_DER_LENGTH_BYTES
  ) {
    return null;
  }

  let length = 0;
  for (let i = 0; i < lengthBytesCount; i += 1) {
    length = (length << 8) | buffer[2 + i];
  }

  return 2 + lengthBytesCount + length;
}

function trimDerPadding(buffer) {
  const expectedLength = parseDerLength(buffer);
  if (expectedLength && expectedLength <= buffer.length) {
    return buffer.slice(0, expectedLength);
  }

  let end = buffer.length;
  while (end > 0 && buffer[end - 1] === 0x00) {
    end -= 1;
  }
  return buffer.slice(0, end);
}

function runOpenSsl(args) {
  const result = spawnSync('openssl', args, { encoding: 'utf8' });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function findCaBundle() {
  const candidates = [
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/etc/ssl/ca-bundle.pem',
    '/usr/local/etc/openssl/cert.pem',
  ];

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function parseSigningTime(cmsText) {
  const match = cmsText.match(/signingTime[\s\S]*?(?:UTCTIME|GENERALIZEDTIME):\s*([^\n\r]+)/i);
  if (!match) {
    return null;
  }

  const rawValue = match[1].trim();
  const parsed = new Date(rawValue);
  if (Number.isNaN(parsed.getTime())) {
    return rawValue;
  }
  return parsed.toISOString();
}

function parseCertificateInfo(certText) {
  const subjectMatch = certText.match(/\bSubject:\s*(.+)/i);
  const issuerMatch = certText.match(/\bIssuer:\s*(.+)/i);
  const notBeforeMatch = certText.match(/\bNot Before:\s*(.+)/i);
  const notAfterMatch = certText.match(/\bNot After\s*:\s*(.+)/i);

  return {
    subject: subjectMatch ? subjectMatch[1].trim() : null,
    issuer: issuerMatch ? issuerMatch[1].trim() : null,
    validFrom: notBeforeMatch ? notBeforeMatch[1].trim() : null,
    validTo: notAfterMatch ? notAfterMatch[1].trim() : null,
    rawText: certText.trim(),
  };
}

function parseHexSignature(hexString) {
  const normalized = (hexString || '').replace(/[^0-9a-fA-F]/g, '');
  const evenHex = normalized.length % 2 === 0 ? normalized : normalized.slice(0, -1);
  if (!evenHex) {
    return null;
  }
  return trimDerPadding(Buffer.from(evenHex, 'hex'));
}

function extractContentsHex(pdfText, byteRange) {
  const firstRangeEnd = byteRange[0] + byteRange[1];
  const secondRangeStart = byteRange[2];
  const markerSearchLowerBound = Math.max(0, firstRangeEnd - CONTENTS_SEARCH_WINDOW_BYTES);

  const markerIndex = pdfText.lastIndexOf('/Contents', secondRangeStart);
  if (markerIndex >= markerSearchLowerBound) {
    const open = pdfText.indexOf('<', markerIndex);
    const close = open >= 0 ? pdfText.indexOf('>', open + 1) : -1;
    if (open >= markerIndex && close > open && close <= secondRangeStart) {
      return pdfText.slice(open + 1, close);
    }
  }

  const gap = pdfText.slice(firstRangeEnd, secondRangeStart);
  let longest = '';
  const regex = /<([0-9a-fA-F\s]+)>/g;
  let match = regex.exec(gap);
  while (match) {
    if (match[1].length > longest.length) {
      longest = match[1];
    }
    match = regex.exec(gap);
  }

  return longest || null;
}

function extractPdfSignatures(pdfBuffer) {
  const pdfText = pdfBuffer.toString('latin1');
  const signatures = [];
  const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;

  let match = byteRangeRegex.exec(pdfText);
  while (match) {
    const byteRange = match.slice(1, 5).map((value) => Number.parseInt(value, 10));
    const [start1, len1, start2, len2] = byteRange;

    const inBounds =
      start1 >= 0 &&
      len1 >= 0 &&
      start2 >= 0 &&
      len2 >= 0 &&
      start1 + len1 <= pdfBuffer.length &&
      start2 + len2 <= pdfBuffer.length;

    if (!inBounds) {
      match = byteRangeRegex.exec(pdfText);
      continue;
    }

    const signatureHex = extractContentsHex(pdfText, byteRange);
    const signatureDer = parseHexSignature(signatureHex);
    const signedContent = Buffer.concat([
      pdfBuffer.slice(start1, start1 + len1),
      pdfBuffer.slice(start2, start2 + len2),
    ]);

    signatures.push({
      byteRange,
      signatureDer,
      signedContent,
      byteRangeCoversWholeFile: start1 === 0 && start1 + len1 <= start2 && start2 + len2 === pdfBuffer.length,
    });

    match = byteRangeRegex.exec(pdfText);
  }

  return signatures;
}

function analyzeSingleSignature(signature, index) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verifypdf-'));
  const signaturePath = path.join(tmpDir, `signature-${index}.der`);
  const contentPath = path.join(tmpDir, `content-${index}.bin`);

  let certInfo = { subject: null, issuer: null, validFrom: null, validTo: null, rawText: '' };
  let cryptographicIntegrityValid = false;
  let certificateTrusted = null;
  let certificateTrustReason = null;
  let signingTime = null;
  let signingTimeWithinCertificateValidity = null;
  let trustedTimestampTokenPresent = false;

  try {
    if (!signature.signatureDer || signature.signatureDer.length === 0) {
      return {
        signatureIndex: index,
        byteRange: signature.byteRange,
        certificateInfo: certInfo,
        signatureVerification: {
          cryptographicIntegrityValid: false,
          certificateTrusted: null,
          certificateTrustReason: 'No CMS signature bytes found in /Contents.',
        },
        timestampVerification: {
          signingTime: null,
          signingTimeWithinCertificateValidity: null,
          trustedTimestampTokenPresent: false,
        },
        tamperCheck: {
          byteRangeCoversWholeFile: signature.byteRangeCoversWholeFile,
          signedDataUntampered: false,
          likelyTampered: true,
        },
      };
    }

    fs.writeFileSync(signaturePath, signature.signatureDer);
    fs.writeFileSync(contentPath, signature.signedContent);

    const integrityResult = runOpenSsl([
      'cms',
      '-verify',
      '-inform',
      'DER',
      '-in',
      signaturePath,
      '-binary',
      '-content',
      contentPath,
      '-noverify',
      '-out',
      os.devNull,
    ]);
    cryptographicIntegrityValid = integrityResult.ok;

    const certTextResult = runOpenSsl([
      'pkcs7',
      '-inform',
      'DER',
      '-in',
      signaturePath,
      '-print_certs',
      '-text',
      '-noout',
    ]);
    if (certTextResult.ok) {
      certInfo = parseCertificateInfo(certTextResult.stdout);
    }

    const caBundle = findCaBundle();
    if (caBundle) {
      const trustResult = runOpenSsl([
        'cms',
        '-verify',
        '-inform',
        'DER',
        '-in',
        signaturePath,
        '-binary',
        '-content',
        contentPath,
        '-CAfile',
        caBundle,
        '-purpose',
        'any',
        '-out',
        os.devNull,
      ]);

      certificateTrusted = trustResult.ok;
      certificateTrustReason = trustResult.ok
        ? `Signer certificate chain validated against ${caBundle}.`
        : trustResult.stderr.trim() || 'Failed to validate signer certificate chain.';
    } else {
      certificateTrusted = null;
      certificateTrustReason = 'No CA bundle found on this system; trust validation was not performed.';
    }

    const cmsPrintResult = runOpenSsl(['cms', '-inform', 'DER', '-in', signaturePath, '-cmsout', '-print']);
    if (cmsPrintResult.ok) {
      signingTime = parseSigningTime(cmsPrintResult.stdout);
      trustedTimestampTokenPresent =
        cmsPrintResult.stdout.includes('id-smime-aa-timeStampToken') ||
        cmsPrintResult.stdout.includes('1.2.840.113549.1.9.16.2.14');
    }

    if (signingTime && certInfo.validFrom && certInfo.validTo) {
      const signDate = new Date(signingTime);
      const validFrom = new Date(certInfo.validFrom);
      const validTo = new Date(certInfo.validTo);
      if (!Number.isNaN(signDate.getTime()) && !Number.isNaN(validFrom.getTime()) && !Number.isNaN(validTo.getTime())) {
        signingTimeWithinCertificateValidity = signDate >= validFrom && signDate <= validTo;
      }
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  return {
    signatureIndex: index,
    byteRange: signature.byteRange,
    certificateInfo: certInfo,
    signatureVerification: {
      cryptographicIntegrityValid,
      certificateTrusted,
      certificateTrustReason,
    },
    timestampVerification: {
      signingTime,
      signingTimeWithinCertificateValidity,
      trustedTimestampTokenPresent,
    },
    tamperCheck: {
      byteRangeCoversWholeFile: signature.byteRangeCoversWholeFile,
      signedDataUntampered: cryptographicIntegrityValid,
      likelyTampered: !signature.byteRangeCoversWholeFile || !cryptographicIntegrityValid,
    },
  };
}

function analyzePdfBuffer(pdfBuffer) {
  const signatures = extractPdfSignatures(pdfBuffer);
  if (signatures.length === 0) {
    return {
      isSigned: false,
      hasSignerCertificate: false,
      pfxAssessment: 'No signature found.',
      message: 'No PDF signature (/ByteRange) found.',
      signatures: [],
    };
  }

  const analyzed = signatures.map((signature, index) => analyzeSingleSignature(signature, index + 1));
  const hasSignerCertificate = analyzed.some((item) => Boolean(item.certificateInfo.subject));

  return {
    isSigned: true,
    hasSignerCertificate,
    pfxAssessment:
      'PFX/PKCS#12 is a key container format and cannot be proven directly from PDF bytes. hasSignerCertificate=true indicates a certificate-based CMS signature, which is commonly created using PFX certificates.',
    signatures: analyzed,
  };
}

function analyzePdfFile(filePath) {
  const pdfBuffer = fs.readFileSync(filePath);
  return analyzePdfBuffer(pdfBuffer);
}

module.exports = {
  analyzePdfFile,
  analyzePdfBuffer,
  extractPdfSignatures,
};
