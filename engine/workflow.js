
'use strict';

const VALID_STATUSES = [
  'open',
  'in_progress',
  'reopened',
  'fixed',
  'accepted_risk',
  'false_positive'
];

const MAX_REASON_LENGTH = 500;

function validationError(message) {
  return {
    error: 'E_VALIDATION',
    message
  };
}

function changeStatus(finding, action, data = {}, role, context = {}) {
  // Validate the finding.
  if (!finding || typeof finding !== 'object' || Array.isArray(finding)) {
    return validationError('A valid finding object is required.');
  }

  if (!VALID_STATUSES.includes(finding.status)) {
    return validationError('Finding has an invalid or missing status.');
  }

  if (
    finding.events !== undefined &&
    !Array.isArray(finding.events)
  ) {
    return validationError('Finding event history must be an array.');
  }

  // Validate request data.
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return validationError('Request data must be a valid object.');
  }

  // Require a trusted actor identity from the backend.
  const actorId = typeof context?.actorId === 'string'
    ? context.actorId.trim()
    : '';

  if (!actorId) {
    return validationError('An authenticated actor identity is required.');
  }

  const transitions = {
    start_work: {
      allowedStatuses: ['open', 'reopened'],
      newStatus: 'in_progress',
      allowedRoles: ['analyst', 'admin']
    },
    accept_risk: {
      allowedStatuses: ['open', 'in_progress', 'reopened'],
      newStatus: 'accepted_risk',
      allowedRoles: ['admin']
    },
    mark_false_positive: {
      allowedStatuses: ['open', 'in_progress', 'reopened'],
      newStatus: 'false_positive',
      allowedRoles: ['analyst', 'admin']
    },
    mark_fixed: {
      allowedStatuses: ['in_progress'],
      newStatus: 'fixed',
      allowedRoles: ['analyst', 'admin']
    }
  };

  const transition = transitions[action];

  if (!transition) {
    return validationError('Unknown status transition action.');
  }

  if (!transition.allowedRoles.includes(role)) {
    return {
      error: 'E_FORBIDDEN',
      message: 'Your role is not allowed to perform this action.'
    };
  }

  if (!transition.allowedStatuses.includes(finding.status)) {
    return validationError(
      `Cannot perform ${action} when finding status is ${finding.status}.`
    );
  }

  // Validate reason where required.
  const reason = typeof data.reason === 'string'
    ? data.reason.trim()
    : '';

  if (
    action === 'accept_risk' ||
    action === 'mark_false_positive'
  ) {
    if (!reason) {
      return validationError('A reason is required for this action.');
    }

    if (reason.length > MAX_REASON_LENGTH) {
      return validationError(
        `Reason cannot exceed ${MAX_REASON_LENGTH} characters.`
      );
    }
  }

  // Validate risk acceptance end date.
  if (action === 'accept_risk') {
    if (
      typeof data.endDate !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}$/.test(data.endDate)
    ) {
      return validationError(
        'A valid end date in YYYY-MM-DD format is required.'
      );
    }

    const endDate = new Date(`${data.endDate}T00:00:00.000Z`);

    if (
      Number.isNaN(endDate.getTime()) ||
      endDate.toISOString().slice(0, 10) !== data.endDate
    ) {
      return validationError('The risk acceptance end date is invalid.');
    }

    const today = new Date().toISOString().slice(0, 10);

    if (data.endDate <= today) {
      return validationError(
        'The risk acceptance end date must be in the future.'
      );
    }
  }

  // Generate the audit timestamp on the server.
  // Never accept the timestamp from request data.
  const timestamp = new Date().toISOString();

  const event = {
    action,
    user: actorId,
    time: timestamp,
    note: reason
  };

  const updatedFinding = {
    ...finding,
    status: transition.newStatus,
    events: [
      ...(finding.events || []),
      event
    ]
  };

  // Keep fixedAt consistent with the finding's current status.
  if (action === 'mark_fixed') {
    updatedFinding.fixedAt = timestamp;
  } else {
    delete updatedFinding.fixedAt;
  }

  if (action === 'accept_risk') {
    updatedFinding.endDate = data.endDate;
  }

  return updatedFinding;
}

module.exports = {
  changeStatus,
  VALID_STATUSES
};
