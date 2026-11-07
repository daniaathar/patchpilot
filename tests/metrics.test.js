'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { computeMetrics } = require('../engine/metrics');

const NOW = '2026-11-07T12:00:00.000Z';

function createFinding(overrides = {}) {
  return {
    id: 'F-101',
    priority: 'High',
    owner: 'Web Team',
    status: 'open',
    firstSeen: '2026-11-01',
    ...overrides
  };
}

test('calculates total number of findings', () => {
  const findings = [
    createFinding(),
    createFinding({ id: 'F-102' }),
    createFinding({ id: 'F-103' })
  ];

  assert.equal(computeMetrics(findings, NOW).total, 3);
});

test('counts open and reopened findings', () => {
  const findings = [
    createFinding({ status: 'open' }),
    createFinding({ status: 'reopened' }),
    createFinding({ status: 'fixed' })
  ];

  assert.equal(computeMetrics(findings, NOW).open, 2);
});

test('counts fixed findings', () => {
  const findings = [
    createFinding({ status: 'fixed' }),
    createFinding({ status: 'open' })
  ];

  assert.equal(computeMetrics(findings, NOW).fixed, 1);
});

test('groups findings by priority', () => {
  const findings = [
    createFinding({ priority: 'Critical' }),
    createFinding({ priority: 'High' }),
    createFinding({ priority: 'High' }),
    createFinding({ priority: 'Medium' })
  ];

  const result = computeMetrics(findings, NOW);

  assert.deepEqual(result.byPriority, {
    Critical: 1,
    High: 2,
    Medium: 1,
    Low: 0
  });
});

test('groups findings by owner', () => {
  const findings = [
    createFinding({ owner: 'Web Team' }),
    createFinding({ owner: 'Web Team' }),
    createFinding({ owner: 'Database Team' })
  ];

  const result = computeMetrics(findings, NOW);

  assert.equal(result.byOwner['Web Team'], 2);
  assert.equal(result.byOwner['Database Team'], 1);
});

test('assigns missing owners to Unassigned', () => {
  const result = computeMetrics([
    createFinding({ owner: undefined })
  ], NOW);

  assert.equal(result.byOwner.Unassigned, 1);
});

test('counts overdue findings', () => {
  const findings = [
    createFinding({
      priority: 'High',
      firstSeen: '2026-10-01'
    })
  ];

  assert.equal(computeMetrics(findings, NOW).overdue, 1);
});

test('excludes fixed findings from overdue count', () => {
  const findings = [
    createFinding({
      status: 'fixed',
      firstSeen: '2026-09-01'
    })
  ];

  assert.equal(computeMetrics(findings, NOW).overdue, 0);
});

test('excludes accepted risk and false positives from SLA calculation', () => {
  const findings = [
    createFinding({ status: 'accepted_risk' }),
    createFinding({ status: 'false_positive' })
  ];

  const result = computeMetrics(findings, NOW);

  assert.equal(result.overdue, 0);
  assert.equal(result.slaPercent, 0);
});

test('calculates SLA compliance percentage', () => {
  const findings = [
    createFinding({
      priority: 'High',
      firstSeen: '2026-11-01'
    }),
    createFinding({
      priority: 'High',
      firstSeen: '2026-10-01'
    })
  ];

  assert.equal(computeMetrics(findings, NOW).slaPercent, 50);
});

test('calculates reopen rate', () => {
  const findings = [
    createFinding({ status: 'reopened' }),
    createFinding({ status: 'open' }),
    createFinding({ status: 'fixed' }),
    createFinding({ status: 'open' })
  ];

  assert.equal(computeMetrics(findings, NOW).reopenRate, 25);
});

test('calculates average days to fix', () => {
  const findings = [
    createFinding({
      status: 'fixed',
      firstSeen: '2026-11-01',
      fixedAt: '2026-11-05'
    }),
    createFinding({
      status: 'fixed',
      firstSeen: '2026-11-01',
      fixedAt: '2026-11-07'
    })
  ];

  assert.equal(computeMetrics(findings, NOW).avgDaysToFix, 5);
});

test('returns zero averages when no fixed findings have valid dates', () => {
  const findings = [
    createFinding({ status: 'fixed' })
  ];

  assert.equal(computeMetrics(findings, NOW).avgDaysToFix, 0);
});

test('handles an empty findings array', () => {
  const result = computeMetrics([], NOW);

  assert.equal(result.total, 0);
  assert.equal(result.open, 0);
  assert.equal(result.overdue, 0);
  assert.equal(result.slaPercent, 0);
  assert.equal(result.reopenRate, 0);
  assert.equal(result.avgDaysToFix, 0);
});

test('rejects invalid findings input', () => {
  assert.throws(
    () => computeMetrics(null, NOW),
    TypeError
  );
});

test('rejects an invalid current date', () => {
  assert.throws(
    () => computeMetrics([], 'invalid-date'),
    TypeError
  );
});