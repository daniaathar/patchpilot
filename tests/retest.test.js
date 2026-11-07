'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { handleRetest } = require('../engine/retest');

const FIXED_DATE = '2026-11-07T10:00:00.000Z';

function createFinding(overrides = {}) {
  return {
    id: 'F-101',
    asset: 'web-server-01',
    priority: 'High',
    status: 'in_progress',
    firstSeen: '2026-10-01',
    events: [],
    ...overrides
  };
}

test('successful retest changes status to fixed', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    'Vulnerability no longer detected.',
    FIXED_DATE
  );

  assert.equal(result.status, 'fixed');
});

test('failed retest changes status to reopened', () => {
  const result = handleRetest(
    createFinding(),
    'fail',
    'Vulnerability is still present.',
    FIXED_DATE
  );

  assert.equal(result.status, 'reopened');
});

test('failed retest calculates a fresh SLA deadline', () => {
  const result = handleRetest(
    createFinding(),
    'fail',
    'Issue still exists.',
    FIXED_DATE
  );

  // High priority has a default SLA of 14 days.
  assert.equal(result.dueDate, '2026-11-21');
});

test('successful retest does not calculate a new SLA deadline', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    'Issue resolved.',
    FIXED_DATE
  );

  assert.equal(result.dueDate, undefined);
});

test('retest evidence is stored after trimming whitespace', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    '  Issue resolved.  ',
    FIXED_DATE
  );

  assert.equal(result.retestEvidence, 'Issue resolved.');
});

test('evidence longer than 500 characters is truncated', () => {
  const evidence = 'A'.repeat(600);

  const result = handleRetest(
    createFinding(),
    'pass',
    evidence,
    FIXED_DATE
  );

  assert.equal(result.retestEvidence.length, 500);
});

test('missing evidence returns a validation error', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    '',
    FIXED_DATE
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('non-string evidence returns a validation error', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    123,
    FIXED_DATE
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('invalid retest result returns a validation error', () => {
  const result = handleRetest(
    createFinding(),
    'pending',
    'Retest evidence.',
    FIXED_DATE
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('invalid finding returns a validation error', () => {
  const result = handleRetest(
    null,
    'pass',
    'Retest evidence.',
    FIXED_DATE
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('retest event is added to event history', () => {
  const result = handleRetest(
    createFinding(),
    'pass',
    'Issue resolved.',
    FIXED_DATE
  );

  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].action, 'retest_pass');
  assert.equal(result.events[0].time, FIXED_DATE);
});

test('existing event history is preserved', () => {
  const finding = createFinding({
    events: [
      { action: 'created', user: 'system', time: '2026-10-01' }
    ]
  });

  const result = handleRetest(
    finding,
    'fail',
    'Issue still exists.',
    FIXED_DATE
  );

  assert.equal(result.events.length, 2);
  assert.equal(result.events[0].action, 'created');
});

test('original firstSeen date is preserved after failed retest', () => {
  const finding = createFinding();

  const result = handleRetest(
    finding,
    'fail',
    'Issue still exists.',
    FIXED_DATE
  );

  assert.equal(result.firstSeen, '2026-10-01');
});

test('original finding is not modified', () => {
  const finding = createFinding();

  handleRetest(
    finding,
    'pass',
    'Issue resolved.',
    FIXED_DATE
  );

  assert.equal(finding.status, 'in_progress');
  assert.equal(finding.events.length, 0);
});

test('custom SLA configuration is respected after failed retest', () => {
  const result = handleRetest(
    createFinding(),
    'fail',
    'Issue still exists.',
    FIXED_DATE,
    { sla_high: 5 }
  );

  assert.equal(result.dueDate, '2026-11-12');
});