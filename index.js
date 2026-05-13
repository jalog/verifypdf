#!/usr/bin/env node

const path = require('path');
const { analyzePdfFile } = require('./src/verifypdf');

function main() {
  const inputPath = process.argv[2];
  if (!inputPath) {
    console.error('Usage: verifypdf <path-to-pdf>');
    process.exit(1);
  }

  const absolutePath = path.resolve(process.cwd(), inputPath);

  try {
    const result = analyzePdfFile(absolutePath);
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Failed to analyze PDF: ${error.message}`);
    process.exit(1);
  }
}

main();
