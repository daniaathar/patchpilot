'use strict';

const { calcSla } = require('./sla');

const PRIORITIES = ['Critical', 'High', 'Medium', 'Low'];

const EXCLUDED_STATUSES = [
  'accepted_risk',
  'false_positive',
  'fixed'
];

function computeMetrics(findings, now = new Date()) {
  if (!Array.isArray(findings)) {
    throw new TypeError('Findings must be an array.');
  }

  const currentDate = new Date(now);

  if (Number.isNaN(currentDate.getTime())) {
    throw new TypeError('A valid current date is required.');
  }

  const metrics = {
    total: findings.length,
    open: 0,
    overdue: 0,
    fixed: 0,
    byPriority: {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    },
    byOwner: {},
    slaPercent: 0,
    avgDaysToFix: 0,
    reopenRate: 0
  };

  let eligibleForSla = 0;
  let withinSla = 0;
  let reopenedCount = 0;
  let totalDaysToFix = 0;
  let fixedWithDates = 0;

  for (const finding of findings) {
    if (!finding || typeof finding !== 'object') {
      continue;
    }

    const status = finding.status || 'open';

    // Count open and reopened findings.
    if (status === 'open' || status === 'reopened') {
      metrics.open++;
    }

    if (status === 'fixed') {
      metrics.fixed++;
    }

    if (status === 'reopened') {
      reopenedCount++;
    }

    // Count findings by priority.
    const priority = PRIORITIES.includes(finding.priority)
      ? finding.priority
      : 'Low';

    metrics.byPriority[priority]++;

    // Count findings by owner.
    const owner = finding.owner || 'Unassigned';

    metrics.byOwner[owner] =
      (metrics.byOwner[owner] || 0) + 1;

    // Calculate SLA statistics for eligible findings.
    if (!EXCLUDED_STATUSES.includes(status)) {
  const calculatedSla = calcSla(finding, {}, currentDate);

  // Use the stored deadline after a failed retest.
  // Otherwise, use the calculated SLA deadline.
  const storedDueDate = finding.dueDate;

  const dueDate = typeof storedDueDate === 'string' &&
    /^\d{4}-\d{2}-\d{2}$/.test(storedDueDate) &&
    !Number.isNaN(Date.parse(`${storedDueDate}T00:00:00Z`)) &&
    new Date(`${storedDueDate}T00:00:00Z`).toISOString().slice(0, 10) === storedDueDate
      ? storedDueDate
      : calculatedSla.dueDate;

  const today = currentDate.toISOString().slice(0, 10);
  const overdue = dueDate < today;

  eligibleForSla++;

  if (overdue) {
    metrics.overdue++;
  } else {
    withinSla++;
  }
}

    // Calculate average time taken to fix findings.
    if (status === 'fixed' && finding.firstSeen && finding.fixedAt) {
      const firstSeen = new Date(finding.firstSeen);
      const fixedAt = new Date(finding.fixedAt);

      if (
        !Number.isNaN(firstSeen.getTime()) &&
        !Number.isNaN(fixedAt.getTime()) &&
        fixedAt >= firstSeen
      ) {
        const days = Math.floor(
          (Date.UTC(
            fixedAt.getUTCFullYear(),
            fixedAt.getUTCMonth(),
            fixedAt.getUTCDate()
          ) - Date.UTC(
            firstSeen.getUTCFullYear(),
            firstSeen.getUTCMonth(),
            firstSeen.getUTCDate()
          )) / 86400000
        );

        totalDaysToFix += days;
        fixedWithDates++;
      }
    }
  }

  metrics.slaPercent = eligibleForSla > 0
    ? Number(((withinSla / eligibleForSla) * 100).toFixed(2))
    : 0;

  metrics.reopenRate = metrics.total > 0
    ? Number(((reopenedCount / metrics.total) * 100).toFixed(2))
    : 0;

  metrics.avgDaysToFix = fixedWithDates > 0
    ? Number((totalDaysToFix / fixedWithDates).toFixed(2))
    : 0;

  return metrics;
}

module.exports = { computeMetrics };