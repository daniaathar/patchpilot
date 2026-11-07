
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { changeStatus } = require('../engine/workflow');

function createFinding(status = 'open') {
  return {
    id: 'F-101',
    asset: 'web-server-01',
    status,
    events: []
  };
}

// Simulate trusted context supplied by the backend.
function changeStatusAs(finding, action, data, role, context = {}) {
  return changeStatus(
    finding,
    action,
    data,
    role,
    {
      actorId: 'user-101',
      ...context
    }
  );
}

test('analyst can start work on an open finding', () => {
  const result = changeStatusAs(
    createFinding('open'),
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.status, 'in_progress');
});

test('analyst can start work on a reopened finding', () => {
  const result = changeStatusAs(
    createFinding('reopened'),
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.status, 'in_progress');
});

test('admin can start work on a finding', () => {
  const result = changeStatusAs(
    createFinding(),
    'start_work',
    {},
    'admin'
  );

  assert.equal(result.status, 'in_progress');
});

test('admin can accept risk with a reason and future end date', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    {
      reason: 'Remediation is temporarily postponed.',
      endDate: '2999-12-31'
    },
    'admin'
  );

  assert.equal(result.status, 'accepted_risk');
  assert.equal(result.endDate, '2999-12-31');
});

test('analyst cannot accept risk', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    {
      reason: 'Temporary exception',
      endDate: '2999-12-31'
    },
    'analyst'
  );

  assert.equal(result.error, 'E_FORBIDDEN');
});

test('accept risk requires a reason', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    { endDate: '2999-12-31' },
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('accept risk requires an end date', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    { reason: 'Temporary exception' },
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('analyst can mark a finding as false positive', () => {
  const result = changeStatusAs(
    createFinding(),
    'mark_false_positive',
    { reason: 'Scanner produced an incorrect result.' },
    'analyst'
  );

  assert.equal(result.status, 'false_positive');
});

test('false positive action requires a reason', () => {
  const result = changeStatusAs(
    createFinding(),
    'mark_false_positive',
    {},
    'analyst'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('analyst can mark an in-progress finding as fixed', () => {
  const result = changeStatusAs(
    createFinding('in_progress'),
    'mark_fixed',
    {},
    'analyst'
  );

  assert.equal(result.status, 'fixed');
  assert.ok(result.fixedAt);
  assert.equal(result.events[0].time, result.fixedAt);
});

test('cannot mark an open finding as fixed directly', () => {
  const result = changeStatusAs(
    createFinding('open'),
    'mark_fixed',
    {},
    'analyst'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('invalid action returns a validation error', () => {
  const result = changeStatusAs(
    createFinding(),
    'delete_finding',
    {},
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('successful transition records an audit event', () => {
  const result = changeStatusAs(
    createFinding(),
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].action, 'start_work');
  assert.equal(result.events[0].user, 'user-101');
  assert.ok(!Number.isNaN(Date.parse(result.events[0].time)));
});

test('client cannot forge audit actor identity', () => {
  const result = changeStatusAs(
    createFinding(),
    'start_work',
    { user: 'Administrator' },
    'analyst'
  );

  assert.equal(result.events[0].user, 'user-101');
});

test('client cannot forge audit timestamp', () => {
  const result = changeStatusAs(
    createFinding(),
    'start_work',
    { time: '2000-01-01T00:00:00.000Z' },
    'analyst'
  );

  assert.notEqual(
    result.events[0].time,
    '2000-01-01T00:00:00.000Z'
  );

  assert.ok(!Number.isNaN(Date.parse(result.events[0].time)));
});

test('missing authenticated actor identity is rejected', () => {
  const result = changeStatus(
    createFinding(),
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('blank authenticated actor identity is rejected', () => {
  const result = changeStatus(
    createFinding(),
    'start_work',
    {},
    'analyst',
    { actorId: '   ' }
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('invalid role is rejected', () => {
  const result = changeStatusAs(
    createFinding(),
    'start_work',
    {},
    'guest'
  );

  assert.equal(result.error, 'E_FORBIDDEN');
});

test('invalid risk acceptance date is rejected', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    {
      reason: 'Temporary exception',
      endDate: '2026-02-30'
    },
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('past risk acceptance date is rejected', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    {
      reason: 'Temporary exception',
      endDate: '2000-01-01'
    },
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('risk acceptance date must use YYYY-MM-DD format', () => {
  const result = changeStatusAs(
    createFinding(),
    'accept_risk',
    {
      reason: 'Temporary exception',
      endDate: '31-12-2999'
    },
    'admin'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('reason cannot exceed 500 characters', () => {
  const result = changeStatusAs(
    createFinding(),
    'mark_false_positive',
    { reason: 'A'.repeat(501) },
    'analyst'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('malformed event history is rejected', () => {
  const finding = createFinding();
  finding.events = 'not-an-array';

  const result = changeStatusAs(
    finding,
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.error, 'E_VALIDATION');
});

test('existing events are preserved', () => {
  const finding = createFinding();

  finding.events.push({
    action: 'created',
    user: 'System',
    time: '2026-11-01T10:00:00.000Z',
    note: ''
  });

  const result = changeStatusAs(
    finding,
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.events.length, 2);
  assert.equal(result.events[0].action, 'created');
});

test('original finding is not modified', () => {
  const finding = createFinding('open');
  const originalEvents = [...finding.events];

  changeStatusAs(
    finding,
    'start_work',
    {},
    'analyst'
  );

  assert.equal(finding.status, 'open');
  assert.deepEqual(finding.events, originalEvents);
});

test('fixedAt is removed when a reopened finding starts work', () => {
  const finding = createFinding('reopened');
  finding.fixedAt = '2026-11-01T10:00:00.000Z';

  const result = changeStatusAs(
    finding,
    'start_work',
    {},
    'analyst'
  );

  assert.equal(result.status, 'in_progress');
  assert.equal(Object.hasOwn(result, 'fixedAt'), false);
});

test('fixedAt is removed when a finding is marked false positive', () => {
  const finding = createFinding('in_progress');
  finding.fixedAt = '2026-11-01T10:00:00.000Z';

  const result = changeStatusAs(
    finding,
    'mark_false_positive',
    { reason: 'Incorrect scanner result.' },
    'analyst'
  );

  assert.equal(result.status, 'false_positive');
  assert.equal(Object.hasOwn(result, 'fixedAt'), false);
});
