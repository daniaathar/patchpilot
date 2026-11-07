'use strict';

const { calcSla } = require('./sla');

function handleRetest(finding, result, evidence, now = new Date(), config = {}) {
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
    return {
      error: 'E_VALIDATION',
      message: 'A valid finding object is required.'
    };
  }

  if (!['pass', 'fail'].includes(result)) {
    return {
      error: 'E_VALIDATION',
      message: 'Retest result must be pass or fail.'
    };
  }

  if (typeof evidence !== 'string' || !evidence.trim()) {
    return {
      error: 'E_VALIDATION',
      message: 'Retest evidence is required.'
    };
  }

  // Evidence is trimmed and capped at 500 characters (truncated, not rejected).
  const evidenceText = evidence.trim().slice(0, 500);

  const retestDate = new Date(now);

  if (Number.isNaN(retestDate.getTime())) {
    return {
      error: 'E_VALIDATION',
      message: 'A valid retest date is required.'
    };
  }

  const newStatus = result === 'pass' ? 'fixed' : 'reopened';
if (finding.events !== undefined && !Array.isArray(finding.events)) {
  return {
    error: 'E_VALIDATION',
    message: 'Finding events must be an array.'
  };
}

const updatedFinding = {
  ...finding,
  status: newStatus,
  retestEvidence: evidenceText,
  events: [
    ...(Array.isArray(finding.events) ? finding.events : []),
    {
      action: result === 'pass' ? 'retest_pass' : 'retest_fail',
      user: 'system',
      time: retestDate.toISOString(),
      note: evidenceText
    }
  ]
};

if (result === 'pass') {
  updatedFinding.fixedAt = retestDate.toISOString();
} else {
  // A failed retest means the vulnerability is not fixed.
  delete updatedFinding.fixedAt;
}
  // A failed retest starts a fresh SLA period.
  // Keep the original firstSeen date unchanged.
  if (result === 'fail') {
    const freshSla = calcSla(
      {
        ...finding,
        firstSeen: retestDate,
        status: 'reopened'
      },
      config,
      retestDate
    );

    updatedFinding.dueDate = freshSla.dueDate;
  }

  return updatedFinding;
}

module.exports = { handleRetest };