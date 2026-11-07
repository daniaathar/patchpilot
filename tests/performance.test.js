/**
 * performance.test.js
 * Measures how long parseImport, dedupe, and scoreFinding take on 1000 rows.
 * Owner: Hareem
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const { parseImport } = require('../engine/importer');
const { dedupe }      = require('../engine/dedupe');
const { scoreFinding } = require('../engine/score');

/** Generates n unique valid finding rows as CSV text */
function generateCsv(n) {
  const lines = [
    'title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen'
  ];
  const criticalities = ['low', 'medium', 'high', 'critical'];
  for (let i = 1; i <= n; i++) {
    const crit = criticalities[i % 4];
    const cvssNum = (1 + (i % 10)); // 1–10 cycling (integers, all valid)
    const internet = i % 2 === 0 ? 'true' : 'false';
    lines.push(
      `Vulnerability ${i},CVE-2026-${String(i).padStart(5, '0')},${cvssNum},asset-${i},${crit},${internet},Scanner,2026-10-01`
    );
  }
  return lines.join('\n');
}

test('Performance – parseImport 1000 rows', () => {
  const csv = generateCsv(1000);
  const start = performance.now();
  const { valid, errors } = parseImport(csv, 'csv');
  const elapsed = performance.now() - start;

  assert.equal(valid.length, 1000, 'Expected 1000 valid findings');
  assert.equal(errors.length, 0, 'Expected 0 errors');

  console.log(`Performance – parseImport(1000 rows): ${elapsed.toFixed(2)} ms`);
  // Should comfortably complete in under 2 seconds on any laptop
  assert.ok(elapsed < 2000, `parseImport took ${elapsed.toFixed(2)}ms, expected < 2000ms`);
});

test('Performance – dedupe 1000 rows against empty list', () => {
  const csv = generateCsv(1000);
  const { valid } = parseImport(csv, 'csv');

  const start = performance.now();
  const { unique, duplicates } = dedupe(valid, []);
  const elapsed = performance.now() - start;

  assert.equal(unique.length, 1000, 'Expected 1000 unique findings');
  assert.equal(duplicates.length, 0, 'Expected 0 duplicates');

  console.log(`Performance – dedupe(1000 rows, []): ${elapsed.toFixed(2)} ms`);
  assert.ok(elapsed < 1000, `dedupe took ${elapsed.toFixed(2)}ms, expected < 1000ms`);
});

test('Performance – scoreFinding 1000 findings', () => {
  const csv = generateCsv(1000);
  const { valid } = parseImport(csv, 'csv');

  const start = performance.now();
  for (const finding of valid) {
    scoreFinding(finding, null);
  }
  const elapsed = performance.now() - start;

  console.log(`Performance – scoreFinding(1000 findings): ${elapsed.toFixed(2)} ms`);
  assert.ok(elapsed < 1000, `scoreFinding took ${elapsed.toFixed(2)}ms, expected < 1000ms`);
});

test('Performance – full pipeline (parse + dedupe + score) for 1000 rows', () => {
  const csv = generateCsv(1000);

  const start = performance.now();

  const { valid } = parseImport(csv, 'csv');
  const { unique } = dedupe(valid, []);
  for (const finding of unique) {
    const scored = scoreFinding(finding, null);
    finding.priorityScore = scored.score;
    finding.priority = scored.priority;
    finding.reasons = scored.reasons;
  }

  const elapsed = performance.now() - start;
  console.log(`Performance – full pipeline (1000 rows): ${elapsed.toFixed(2)} ms`);
  assert.ok(elapsed < 3000, `Full pipeline took ${elapsed.toFixed(2)}ms, expected < 3000ms`);
});
