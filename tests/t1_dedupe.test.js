/**
 * T1 – Deduplication Test
 * Run sample_good.csv through parseImport then dedupe.
 * Expect exactly 3 duplicates found (rows 18, 19, 20 duplicate rows 1, 2, 3).
 *
 * Test format: ID, input, expected, actual, evidence, pass/fail
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parseImport } = require('../engine/importer');
const { dedupe } = require('../engine/dedupe');

// ── T1: Deduplication with sample_good.csv ──────────────────────────────────
test('T1 – dedupe finds exactly 3 duplicates in sample_good.csv', () => {
  // Input
  const csvText = fs.readFileSync(
    path.join(__dirname, '../fixtures/sample_good.csv'), 'utf8'
  );

  // Parse the file
  const { valid, errors } = parseImport(csvText, 'csv');

  // All 20 rows should parse without errors
  assert.equal(errors.length, 0,
    `Expected 0 parse errors, got: ${JSON.stringify(errors)}`);
  assert.equal(valid.length, 20, `Expected 20 valid rows, got ${valid.length}`);

  // Run deduplication against an empty existing list
  const { unique, duplicates } = dedupe(valid, []);

  // Expected: 17 unique + 3 duplicates
  const expected = { unique: 17, duplicates: 3 };
  const actual   = { unique: unique.length, duplicates: duplicates.length };

  console.log('T1 Evidence:');
  console.log('  Unique findings  :', unique.length);
  console.log('  Duplicate rows   :', duplicates.length);
  duplicates.forEach((d, i) => {
    console.log(`  Dup ${i + 1}: ${d.reason}`);
  });

  assert.equal(actual.unique, expected.unique,
    `Expected ${expected.unique} unique findings, got ${actual.unique}`);
  assert.equal(actual.duplicates, expected.duplicates,
    `Expected ${expected.duplicates} duplicates, got ${actual.duplicates}`);

  // Each duplicate must have a reason string
  duplicates.forEach(d => {
    assert.ok(d.reason && d.reason.length > 0, 'Each duplicate must have a reason.');
  });

  console.log('T1 RESULT: PASS');
});

// ── T1b: Deduplication with sample_good.json ────────────────────────────────
test('T1b – dedupe finds exactly 3 duplicates in sample_good.json', () => {
  const jsonText = fs.readFileSync(
    path.join(__dirname, '../fixtures/sample_good.json'), 'utf8'
  );

  const { valid, errors } = parseImport(jsonText, 'json');
  assert.equal(errors.length, 0, `Expected 0 parse errors`);
  assert.equal(valid.length, 20, `Expected 20 valid rows`);

  const { unique, duplicates } = dedupe(valid, []);
  assert.equal(unique.length, 17, 'Expected 17 unique findings');
  assert.equal(duplicates.length, 3, 'Expected 3 duplicates');

  console.log('T1b RESULT: PASS');
});

// ── T1c: Dedup against existing list ────────────────────────────────────────
test('T1c – dedupe against existing list flags matches correctly', () => {
  const existing = [
    { id: 'F-0001', cve: 'CVE-2024-9001', asset: 'web-10', firstSeen: '2026-09-01', status: 'open' }
  ];
  const incoming = [
    { id: null, cve: 'CVE-2024-9001', asset: 'web-10', firstSeen: '2026-10-01', status: 'open' },
    { id: null, cve: 'CVE-2024-9002', asset: 'web-10', firstSeen: '2026-10-01', status: 'open' }
  ];

  const { unique, duplicates } = dedupe(incoming, existing);
  assert.equal(unique.length, 1, 'Expected 1 unique finding');
  assert.equal(duplicates.length, 1, 'Expected 1 duplicate');
  assert.equal(duplicates[0].matchedId, 'F-0001', 'Matched ID should be F-0001');

  console.log('T1c RESULT: PASS');
});
