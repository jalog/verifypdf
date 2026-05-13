const test = require('node:test');
const assert = require('node:assert/strict');
const { analyzePdfBuffer, extractPdfSignatures } = require('../src/verifypdf');

test('returns unsigned result when no /ByteRange is present', () => {
  const minimalPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n', 'latin1');
  const result = analyzePdfBuffer(minimalPdf);

  assert.equal(result.isSigned, false);
  assert.equal(result.signatures.length, 0);
});

test('extracts signature metadata and verifies byte range coverage', () => {
  const mockSignedPdfBuffer = Buffer.from('/ByteRange [0 40 60 60] /Contents <3003020100>'.padEnd(120, 'A'), 'latin1');
  const signatures = extractPdfSignatures(mockSignedPdfBuffer);

  assert.equal(signatures.length, 1);
  assert.deepEqual(signatures[0].byteRange, [0, 40, 60, 60]);
  assert.equal(signatures[0].byteRangeCoversWholeFile, true);
  assert.ok(signatures[0].signatureDer);
});
