/**
 * server/stubs.js
 * Placeholder implementations of Hareem's and Easha's engine functions.
 * These are used only during Day 2 integration before real functions are plugged in.
 * Swap to real engine with: const { parseImport } = require('../../Hareem/engine/importer');
 *
 * This file is NOT used in the final integrated app – see engine.js.
 * Owner: Rida
 */

'use strict';

function parseImport(text, type) {
  return { valid: [], errors: [{ row: 0, code: 'E_SERVER', message: 'Stub: not yet integrated.' }] };
}

function dedupe(newList, existingList) {
  return { unique: newList || [], duplicates: [] };
}

function scoreFinding(finding, config) {
  return { score: 50, priority: 'Medium', reasons: ['Stub score'], ruleVersion: 'stub' };
}

function calcSla(finding, config, now) {
  return { dueDate: null, daysLeft: 0, overdue: false, reason: 'Stub SLA' };
}

function assignOwner(finding, ownerRules) {
  return { owner: 'Unassigned', reason: 'Stub owner' };
}

function changeStatus(finding, action, data, role) {
  return { finding, event: { action, user: 'stub', time: new Date().toISOString(), note: 'stub' } };
}

function handleRetest(finding, result, evidence) {
  return { status: result === 'pass' ? 'fixed' : 'reopened', newDueDate: null, reason: 'Stub retest' };
}

function computeMetrics(findings, now) {
  return {
    total: findings.length, open: 0, overdue: 0,
    byPriority: {}, byOwner: {}, slaPercent: 0,
    avgDaysToFix: 0, reopenRate: 0
  };
}

module.exports = { parseImport, dedupe, scoreFinding, calcSla, assignOwner, changeStatus, handleRetest, computeMetrics };
