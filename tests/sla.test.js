
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { calcSla } = require('../engine/sla');

const NOW = '2026-11-07T12:00:00Z';

test('Critical finding gets the default 7-day SLA', () => {
  const result = calcSla({
    priority: 'Critical',
    firstSeen: '2026-11-01',
    status: 'open'
  }, {}, NOW);

  assert.equal(result.dueDate, '2026-11-08');
  assert.equal(result.daysLeft, 1);
  assert.equal(result.overdue, false);
});

test('Custom SLA configuration overrides the default', () => {
  const result = calcSla({
    priority: 'Critical',
    firstSeen: '2026-11-01',
    status: 'open'
  }, { sla_critical: 3 }, NOW);

  assert.equal(result.dueDate, '2026-11-04');
  assert.equal(result.overdue, true);
});

test('Finding becomes overdue after its due date', () => {
  const result = calcSla({
    priority: 'High',
    firstSeen: '2026-10-01',
    status: 'open'
  }, {}, NOW);

  assert.equal(result.overdue, true);
  assert.ok(result.daysLeft < 0);
});

test('Accepted risk is not marked overdue', () => {
  const result = calcSla({
    priority: 'Critical',
    firstSeen: '2026-10-01',
    status: 'accepted_risk'
  }, {}, NOW);

  assert.equal(result.overdue, false);
});

test('False positive is not marked overdue', () => {
  const result = calcSla({
    priority: 'High',
    firstSeen: '2026-10-01',
    status: 'false_positive'
  }, {}, NOW);

  assert.equal(result.overdue, false);
});

test('Fixed finding is not marked overdue', () => {
  const result = calcSla({
    priority: 'Medium',
    firstSeen: '2026-09-01',
    status: 'fixed'
  }, {}, NOW);

  assert.equal(result.overdue, false);
});

test('Missing firstSeen uses the current date', () => {
  const result = calcSla({
    priority: 'Low',
    status: 'open'
  }, {}, NOW);

  assert.equal(result.dueDate, '2027-02-05');
  assert.equal(result.daysLeft, 90);
});

test('Unknown priority falls back to Low', () => {
  const result = calcSla({
    priority: 'Urgent',
    firstSeen: '2026-11-07',
    status: 'open'
  }, {}, NOW);

  assert.equal(result.dueDate, '2027-02-05');
});
