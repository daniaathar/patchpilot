/**
 * additional.test.js
 * 12+ additional unit tests for importer.js, dedupe.js, and score.js
 * Owner: Hareem
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parseImport } = require('../engine/importer');
const { dedupe }      = require('../engine/dedupe');
const { scoreFinding, DEFAULT_CONFIG } = require('../engine/score');

// ─────────────────────────────────────────────────────────────────────────────
// IMPORT TESTS
// ─────────────────────────────────────────────────────────────────────────────

test('Test 01 – rejects file with invalid cvss (99)', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
Bad CVSS,CVE-2024-0002,99,web-02,high,true,Nessus,2026-10-02`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(valid.length, 0, 'Should have 0 valid rows');
  assert.ok(errors.length > 0, 'Should have at least one error');
  assert.ok(errors[0].message.includes('cvss'), 'Error should mention cvss');
  console.log('Test 01 PASS – bad cvss rejected:', errors[0].message);
});

test('Test 02 – rejects row with missing title', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
,CVE-2024-0001,7.5,web-01,high,true,Nessus,2026-10-01`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(valid.length, 0, 'Should have 0 valid rows');
  assert.ok(errors.some(e => e.message.toLowerCase().includes('title')),
    'Error should mention missing title');
  console.log('Test 02 PASS – missing title rejected');
});

test('Test 03 – rejects row with wrong assetCriticality word', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
Test,CVE-2024-0003,5.0,web-03,extreme,false,Qualys,2026-10-03`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(valid.length, 0, 'Should have 0 valid rows');
  assert.ok(errors.some(e => e.message.toLowerCase().includes('assetcriticality')),
    'Error should mention assetCriticality');
  console.log('Test 03 PASS – wrong criticality rejected');
});

test('Test 04 – rejects empty file', () => {
  const { valid, errors } = parseImport('', 'csv');
  assert.equal(valid.length, 0, 'Should have 0 valid rows');
  assert.ok(errors.some(e => e.message.toLowerCase().includes('empty')),
    'Error should mention empty file');
  console.log('Test 04 PASS – empty file rejected');
});

test('Test 05 – formula injection blocked (= prefix in title)', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
=cmd /c calc,CVE-2024-0004,6.0,web-04,medium,true,OpenVAS,2026-10-04`;
  const { valid, errors } = parseImport(csv, 'csv');
  // The row should be rejected because of the dangerous '=' prefix
  assert.ok(
    errors.some(e => e.message.toLowerCase().includes('formula')),
    'Should flag formula injection attempt'
  );
  console.log('Test 05 PASS – formula injection blocked');
});

test('Test 06 – formula injection blocked (+ prefix)', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
+THREAT,CVE-2024-0005,6.0,web-05,medium,false,Nessus,2026-10-05`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.ok(errors.some(e => e.message.toLowerCase().includes('formula')),
    'Should flag + prefix formula injection');
  console.log('Test 06 PASS – + prefix formula injection blocked');
});

test('Test 07 – parses valid JSON array correctly', () => {
  const findings = [
    { title: 'XSS', cve: 'CVE-2024-0010', cvss: 6.5, asset: 'web-10',
      assetCriticality: 'medium', internetFacing: true, scanner: 'Nessus',
      firstSeen: '2026-10-10' }
  ];
  const { valid, errors } = parseImport(JSON.stringify(findings), 'json');
  assert.equal(errors.length, 0, 'Should have 0 errors');
  assert.equal(valid.length, 1, 'Should have 1 valid finding');
  assert.equal(valid[0].cve, 'CVE-2024-0010');
  console.log('Test 07 PASS – valid JSON parsed');
});

test('Test 08 – rejects malformed JSON', () => {
  const { valid, errors } = parseImport('{not valid json}', 'json');
  assert.equal(valid.length, 0, 'Should have 0 valid rows');
  assert.ok(errors.some(e => e.message.toLowerCase().includes('json')),
    'Error should mention JSON');
  console.log('Test 08 PASS – malformed JSON rejected');
});

test('Test 09 – rejects JSON that is not an array', () => {
  const { valid, errors } = parseImport('{"key":"value"}', 'json');
  assert.equal(valid.length, 0);
  assert.ok(errors.some(e => e.message.toLowerCase().includes('array')));
  console.log('Test 09 PASS – JSON object (not array) rejected');
});

test('Test 10 – rejects unknown file type', () => {
  const { valid, errors } = parseImport('some text', 'xml');
  assert.equal(valid.length, 0);
  assert.ok(errors.some(e => e.message.toLowerCase().includes('type')));
  console.log('Test 10 PASS – unknown type rejected');
});

// ─────────────────────────────────────────────────────────────────────────────
// SCORE TESTS
// ─────────────────────────────────────────────────────────────────────────────

test('Test 11 – borderline score 79.9 is High not Critical', () => {
  // Score = cvss*6 + assetPts + internetPts
  // We need something that gives ~79.9 raw
  // cvss=9.0 → 54, assetCriticality=high → 20, internetFacing=false → 0  → 74 (High)
  // cvss=9.0 → 54, assetCriticality=high → 20, internetFacing=true  → 10 → 84 (Critical)
  // To get 79: cvss=8.2 → 49.2, high 20, internet 10 = 79.2 → High
  const finding = {
    cvss: 8.2, assetCriticality: 'high', internetFacing: true
  };
  const result = scoreFinding(finding, null);
  assert.ok(result.score < 80, `Score ${result.score} should be below 80`);
  assert.equal(result.priority, 'High', `Priority should be High, got ${result.priority}`);
  console.log(`Test 11 PASS – score ${result.score} = ${result.priority}`);
});

test('Test 12 – borderline score 80.0 is Critical', () => {
  // cvss=8.33... → 50, critical 30, internet 10 = but let's use exact values
  // cvss=6.7 → 40.2, critical 30, internet 10 = 80.2 → Critical
  const finding = {
    cvss: 6.7, assetCriticality: 'critical', internetFacing: true
  };
  const result = scoreFinding(finding, null);
  assert.ok(result.score >= 80, `Score ${result.score} should be >= 80`);
  assert.equal(result.priority, 'Critical');
  console.log(`Test 12 PASS – score ${result.score} = ${result.priority}`);
});

test('Test 13 – score capped at 100', () => {
  // CVSS 10.0 * 6 = 60, critical 30, internet 10 = 100 (exact cap)
  const finding = { cvss: 10.0, assetCriticality: 'critical', internetFacing: true };
  const result = scoreFinding(finding, null);
  assert.equal(result.score, 100, 'Score should be capped at 100');
  assert.equal(result.priority, 'Critical');
  console.log('Test 13 PASS – score capped at 100');
});

test('Test 14 – low asset, no internet, low CVSS gives Low priority', () => {
  const finding = { cvss: 2.0, assetCriticality: 'low', internetFacing: false };
  const result = scoreFinding(finding, null);
  // 2.0*6=12 + 0 + 0 = 12 → Low
  assert.equal(result.priority, 'Low');
  assert.ok(result.score < 40);
  console.log(`Test 14 PASS – score ${result.score} = Low`);
});

test('Test 15 – changed weights produce different score', () => {
  const finding = { cvss: 5.0, assetCriticality: 'medium', internetFacing: false };

  const defaultResult  = scoreFinding(finding, null);
  // 5.0*6=30 + 10 + 0 = 40 → Medium

  const customConfig = { cvssMultiplier: 10 }; // heavier weight
  const customResult = scoreFinding(finding, customConfig);
  // 5.0*10=50 + 10 + 0 = 60 → High

  assert.notEqual(defaultResult.score, customResult.score,
    'Different weights should produce different scores');
  assert.notEqual(defaultResult.priority, customResult.priority,
    'Different weights should produce different priority');
  console.log(`Test 15 PASS – default: ${defaultResult.score} (${defaultResult.priority}), custom: ${customResult.score} (${customResult.priority})`);
});

test('Test 16 – scoreFinding throws on invalid cvss', () => {
  const finding = { cvss: 'bad', assetCriticality: 'medium', internetFacing: false };
  assert.throws(() => scoreFinding(finding, null), /Invalid cvss/);
  console.log('Test 16 PASS – invalid cvss throws error');
});

test('Test 17 – every score result includes reasons array with content', () => {
  const finding = { cvss: 7.5, assetCriticality: 'high', internetFacing: true };
  const result = scoreFinding(finding, null);
  assert.ok(Array.isArray(result.reasons), 'reasons should be an array');
  assert.ok(result.reasons.length >= 3, 'Should have at least 3 reason entries');
  result.reasons.forEach(r => {
    assert.ok(typeof r === 'string' && r.length > 0, 'Each reason must be a non-empty string');
  });
  console.log('Test 17 PASS – reasons:', result.reasons);
});

test('Test 18 – sample_bad.csv produces only errors, no valid rows', () => {
  const csvText = fs.readFileSync(
    path.join(__dirname, '../fixtures/sample_bad.csv'), 'utf8'
  );
  const { valid, errors } = parseImport(csvText, 'csv');
  assert.equal(valid.length, 0, `Expected 0 valid rows, got ${valid.length}`);
  assert.ok(errors.length > 0, 'Should have errors from bad CSV');
  console.log(`Test 18 PASS – ${errors.length} errors detected in sample_bad.csv`);
  errors.forEach(e => console.log('  Error:', e.message));
});

test('Test 19 – cvss=0 is valid (boundary check)', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
Zero CVSS,CVE-2024-0020,0,web-20,low,false,Nessus,2026-10-20`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(errors.length, 0, `Expected 0 errors, got: ${JSON.stringify(errors)}`);
  assert.equal(valid.length, 1, 'Should accept cvss=0');
  assert.equal(valid[0].cvss, 0);
  console.log('Test 19 PASS – cvss=0 accepted');
});

test('Test 20 – cvss=10 is valid (boundary check)', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
Max CVSS,CVE-2024-0021,10,web-21,critical,true,Nessus,2026-10-21`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(errors.length, 0, `Expected 0 errors`);
  assert.equal(valid.length, 1, 'Should accept cvss=10');
  assert.equal(valid[0].cvss, 10);
  console.log('Test 20 PASS – cvss=10 accepted');
});

test('Test 21 – dedupe preserves the oldest firstSeen date', () => {
  const older = { id: 'F-001', cve: 'CVE-2024-X', asset: 'web-01', firstSeen: '2026-01-01', status: 'open' };
  const newer = { id: null,    cve: 'CVE-2024-X', asset: 'web-01', firstSeen: '2026-06-01', status: 'open' };

  const { unique, duplicates } = dedupe([newer], [older]);
  assert.equal(unique.length, 0, 'No new uniques expected');
  assert.equal(duplicates.length, 1);
  // The existing record (older) should keep its firstSeen
  assert.equal(older.firstSeen, '2026-01-01', 'Older firstSeen should be preserved');
  console.log('Test 21 PASS – oldest firstSeen preserved');
});

test('Test 22 – intra-batch dedup works (two identical rows in same CSV)', () => {
  const rows = [
    { cve: 'CVE-2024-Z', asset: 'db-99', firstSeen: '2026-10-01', status: 'open' },
    { cve: 'CVE-2024-Z', asset: 'db-99', firstSeen: '2026-10-02', status: 'open' }
  ];
  const { unique, duplicates } = dedupe(rows, []);
  assert.equal(unique.length, 1, 'Should keep 1 unique');
  assert.equal(duplicates.length, 1, 'Should flag 1 intra-batch duplicate');
  console.log('Test 22 PASS – intra-batch dedup works');
});

test('Test 23 – missing multiple required fields reports one error per field', () => {
  // Row missing title AND cve AND scanner
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
,,7.5,web-01,high,true,,2026-10-01`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(valid.length, 0);
  // Should report errors for title, cve, and scanner
  const fields = errors.map(e => e.message);
  assert.ok(fields.some(m => m.includes("'title'")), 'Should report missing title');
  assert.ok(fields.some(m => m.includes("'cve'")),   'Should report missing cve');
  assert.ok(fields.some(m => m.includes("'scanner'")), 'Should report missing scanner');
  console.log('Test 23 PASS – multiple missing fields reported individually');
});

test('Test 24 – invalid firstSeen date is rejected with a clear error', () => {
  const csv = `title,cve,cvss,asset,assetCriticality,internetFacing,scanner,firstSeen
Bad Date,CVE-2024-0100,5.0,web-01,low,false,Nessus,not-a-date`;
  const { valid, errors } = parseImport(csv, 'csv');
  assert.equal(valid.length, 0);
  assert.ok(errors.some(e => e.message.includes("'firstSeen'")), 'Should report invalid firstSeen');
  console.log('Test 24 PASS – invalid firstSeen rejected');
});
