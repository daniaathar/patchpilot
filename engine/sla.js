
'use strict';

const DEFAULT_SLA_DAYS = {
  Critical: 7,
  High: 14,
  Medium: 30,
  Low: 90
};

const CONFIG_KEYS = {
  Critical: 'sla_critical',
  High: 'sla_high',
  Medium: 'sla_medium',
  Low: 'sla_low'
};

const EXCLUDED_STATUSES = [
  'accepted_risk',
  'false_positive',
  'fixed'
];

// Convert a date into a UTC date-only value.
// This avoids timezone and time-of-day differences.
function toUtcDate(value) {
  const date = value instanceof Date ? value : new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate()
  );
}

function calcSla(finding, config, now) {
  if (!finding || typeof finding !== 'object') {
    throw new TypeError('A valid finding object is required.');
  }

  const currentDate = now ? new Date(now) : new Date();
  const today = toUtcDate(currentDate);

  if (today === null) {
    throw new TypeError('The supplied current date is invalid.');
  }

  const priority = DEFAULT_SLA_DAYS[finding.priority]
    ? finding.priority
    : 'Low';

  const configKey = CONFIG_KEYS[priority];
  const configuredDays = config && config[configKey] !== undefined
    ? Number.parseInt(config[configKey], 10)
    : DEFAULT_SLA_DAYS[priority];

  const days = Number.isInteger(configuredDays) && configuredDays >= 0
    ? configuredDays
    : DEFAULT_SLA_DAYS[priority];

  // If firstSeen is missing or invalid, use the current date.
  const firstSeen = toUtcDate(finding.firstSeen) ?? today;

  const dueTimestamp = firstSeen + days * 86400000;
  const dueDate = new Date(dueTimestamp).toISOString().slice(0, 10);

  const daysLeft = Math.round(
    (dueTimestamp - today) / 86400000
  );

  const status = finding.status || 'open';
  const overdue = daysLeft < 0 &&
    !EXCLUDED_STATUSES.includes(status);

  return {
    dueDate,
    daysLeft,
    overdue,
    reason: `${priority} finding SLA is ${days} days from firstSeen. Due: ${dueDate}.`
  };
}

module.exports = { calcSla };
