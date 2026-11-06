/**
 * server/engine.js
 * Single integration point: imports Hareem's real engine functions.
 * Easha's functions (sla, owner, workflow, retest, metrics) are stubbed here
 * and should be replaced when Easha's engine is available.
 *
 * To integrate Easha's functions, replace the stub exports below with:
 *   const { calcSla }       = require('../../Easha/engine/sla');
 *   const { assignOwner }   = require('../../Easha/engine/owner');
 *   const { changeStatus }  = require('../../Easha/engine/workflow');
 *   const { handleRetest }  = require('../../Easha/engine/retest');
 *   const { computeMetrics }= require('../../Easha/engine/metrics');
 *
 * Owner: Rida
 */

'use strict';

const path = require('path');

// ── Hareem's real engine functions ───────────────────────────────────────────
const { parseImport } = require(path.join(__dirname, '../../Hareem/engine/importer'));
const { dedupe }      = require(path.join(__dirname, '../../Hareem/engine/dedupe'));
const { scoreFinding }= require(path.join(__dirname, '../../Hareem/engine/score'));

/**
 * Translates the flat DB config keys into the nested object shape that
 * Hareem's scoreFinding() expects.
 *
 * DB stores:   cvssMultiplier, assetPoints_low, assetPoints_medium,
 *              assetPoints_high, assetPoints_critical, internetFacingBonus,
 *              sla_critical, sla_high, sla_medium, sla_low
 *
 * scoreFinding expects:
 *   { cvssMultiplier, assetPoints: { low, medium, high, critical },
 *     internetFacingBonus, maxScore, priorityBands, ruleVersion }
 */
function buildScoreConfig(dbConfig) {
  if (!dbConfig) return null; // use defaults inside scoreFinding
  return {
    cvssMultiplier:     parseFloat(dbConfig.cvssMultiplier   || 6),
    internetFacingBonus:parseFloat(dbConfig.internetFacingBonus || 10),
    assetPoints: {
      low:      parseFloat(dbConfig.assetPoints_low      || 0),
      medium:   parseFloat(dbConfig.assetPoints_medium   || 10),
      high:     parseFloat(dbConfig.assetPoints_high     || 20),
      critical: parseFloat(dbConfig.assetPoints_critical || 30)
    }
    // maxScore and priorityBands use scoreFinding's own defaults
  };
}

// ── Easha's functions (stubs until her engine is ready) ──────────────────────

/**
 * calcSla – assigns a due date to a finding based on its priority.
 * Stub implementation; replace with Easha's engine/sla.js when ready.
 */
function calcSla(finding, config, now) {
  const slaDays = {
    Critical: parseInt(config.sla_critical || '7'),
    High:     parseInt(config.sla_high     || '14'),
    Medium:   parseInt(config.sla_medium   || '30'),
    Low:      parseInt(config.sla_low      || '90')
  };

  const priority = finding.priority || 'Low';
  const days     = slaDays[priority] || 90;
  const base     = new Date(finding.firstSeen || now);
  const due      = new Date(base.getTime() + days * 86400000);
  const dueDate  = due.toISOString().slice(0, 10);
  const today    = new Date(now);
  const daysLeft = Math.ceil((due - today) / 86400000);
  const nonOverdueStatuses = ['accepted_risk', 'false_positive', 'fixed'];
  const overdue  = today > due && !nonOverdueStatuses.includes(finding.status);

  return {
    dueDate,
    daysLeft,
    overdue,
    reason: `${priority} finding SLA is ${days} days from firstSeen (${finding.firstSeen || 'today'}). Due: ${dueDate}.`
  };
}

/**
 * assignOwner – picks the team responsible for fixing this finding.
 * Stub implementation; replace with Easha's engine/owner.js when ready.
 */
function assignOwner(finding, ownerRules) {
  const rules = ownerRules || [
    { prefix: 'web-',  owner: 'Web Team'      },
    { prefix: 'db-',   owner: 'Database Team' },
    { prefix: 'app-',  owner: 'App Team'      },
    { prefix: 'net-',  owner: 'Network Team'  },
    { prefix: 'win-',  owner: 'Windows Team'  },
    { prefix: 'api-',  owner: 'API Team'      },
    { prefix: 'file-', owner: 'Storage Team'  }
  ];

  const asset = String(finding.asset || '').toLowerCase();
  for (const rule of rules) {
    if (asset.startsWith(rule.prefix)) {
      return { owner: rule.owner, reason: `Asset '${finding.asset}' matches prefix '${rule.prefix}'.` };
    }
  }
  return { owner: 'Unassigned', reason: `No ownership rule matched asset '${finding.asset}'.` };
}

/**
 * changeStatus – transitions a finding through its lifecycle states.
 * Stub implementation; replace with Easha's engine/workflow.js when ready.
 */
function changeStatus(finding, action, data, role) {
  const allowedTransitions = {
    start_work:          { from: ['open', 'reopened'], to: 'in_progress', roles: ['analyst','admin'] },
    accept_risk:         { from: ['open','in_progress','reopened'], to: 'accepted_risk', roles: ['admin'] },
    mark_false_positive: { from: ['open','in_progress','reopened'], to: 'false_positive', roles: ['analyst','admin'] },
    mark_fixed:          { from: ['in_progress'], to: 'fixed', roles: ['analyst','admin'] }
  };

  const transition = allowedTransitions[action];
  if (!transition) {
    return { error: 'E_VALIDATION', message: `Unknown action '${action}'.` };
  }
  if (!transition.roles.includes(role)) {
    return { error: 'E_FORBIDDEN', message: `Role '${role}' cannot perform '${action}'.` };
  }
  if (!transition.from.includes(finding.status)) {
    return { error: 'E_VALIDATION', message: `Cannot '${action}' a finding with status '${finding.status}'.` };
  }

  // accept_risk requires a written reason and end date
  if (action === 'accept_risk' && (!data || !data.reason || !data.endDate)) {
    return { error: 'E_VALIDATION', message: `'accept_risk' requires 'reason' and 'endDate'.` };
  }

  // mark_false_positive requires a written reason
  if (action === 'mark_false_positive' && (!data || !data.reason)) {
    return { error: 'E_VALIDATION', message: `'mark_false_positive' requires 'reason'.` };
  }

  const event = {
    action,
    user: data && data.user ? data.user : 'unknown',
    time: new Date().toISOString(),
    note: data && data.reason ? data.reason : action
  };

  const updatedFinding = Object.assign({}, finding, { status: transition.to });
  return { finding: updatedFinding, event };
}

/**
 * handleRetest – processes a retest result (pass = fixed, fail = reopened).
 * Stub implementation; replace with Easha's engine/retest.js when ready.
 */
function handleRetest(finding, result, evidence) {
  if (!evidence || evidence.trim() === '') {
    return { error: 'E_VALIDATION', message: 'Evidence text is required for retest.' };
  }
  const cleanEvidence = evidence.trim().slice(0, 500);

  if (result === 'pass') {
    return { status: 'fixed', newDueDate: null, reason: `Retest passed. Evidence: ${cleanEvidence}` };
  } else if (result === 'fail') {
    // Reopen with a new due date based on current priority
    const now      = new Date();
    const slaDays  = { Critical: 7, High: 14, Medium: 30, Low: 90 };
    const days     = slaDays[finding.priority] || 30;
    const newDue   = new Date(now.getTime() + days * 86400000).toISOString().slice(0, 10);
    return { status: 'reopened', newDueDate: newDue, reason: `Retest failed. Evidence: ${cleanEvidence}. New due date: ${newDue}.` };
  } else {
    return { error: 'E_VALIDATION', message: `Result must be 'pass' or 'fail' (got '${result}').` };
  }
}

/**
 * computeMetrics – aggregates dashboard numbers from all findings.
 * Stub implementation; replace with Easha's engine/metrics.js when ready.
 */
function computeMetrics(findings, now) {
  const today = new Date(now);
  const nonOverdue = ['accepted_risk', 'false_positive', 'fixed'];

  const total    = findings.length;
  const open     = findings.filter(f => ['open','in_progress','reopened'].includes(f.status)).length;
  const overdue  = findings.filter(f => f.dueDate && new Date(f.dueDate) < today && !nonOverdue.includes(f.status)).length;
  const fixed    = findings.filter(f => f.status === 'fixed').length;
  const reopened = findings.filter(f => f.status === 'reopened').length;

  const byPriority = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const byOwner    = {};

  for (const f of findings) {
    if (f.priority && byPriority[f.priority] !== undefined) byPriority[f.priority]++;
    const owner = f.owner || 'Unassigned';
    byOwner[owner] = (byOwner[owner] || 0) + 1;
  }

  const withDue = findings.filter(f => f.dueDate);
  const slaCompliant = withDue.filter(f => new Date(f.dueDate) >= today || nonOverdue.includes(f.status));
  const slaPercent   = withDue.length > 0 ? Math.round((slaCompliant.length / withDue.length) * 100) : 100;

  const reopenRate   = total > 0 ? parseFloat(((reopened / total) * 100).toFixed(1)) : 0;

  return {
    total, open, overdue, fixed,
    byPriority, byOwner,
    slaPercent,
    reopenRate
  };
}

module.exports = { parseImport, dedupe, scoreFinding, buildScoreConfig, calcSla, assignOwner, changeStatus, handleRetest, computeMetrics };
