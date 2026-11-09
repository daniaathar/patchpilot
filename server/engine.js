/**
 * server/engine.js
 * Single integration point between the API (routes.js) and the real engine.
 *
 *   Hareem: parseImport, dedupe, scoreFinding           (engine/importer, dedupe, score)
 *   Easha:  calcSla, assignOwner, changeStatus,
 *           handleRetest, computeMetrics                (engine/sla, owner, workflow, retest, metrics)
 *
 * Contracts routes.js relies on (these differ from the shared doc):
 *   changeStatus(finding, action, data, role, context) -> whole updated finding
 *     - context.actorId MUST be the logged-in user's id from the session, as a
 *       string. Any user/actor sent in the request body is ignored on purpose
 *       (audit log integrity).
 *   handleRetest(finding, result, evidence, now, config) -> whole updated finding
 *   Both append the new audit entry to finding.events; read it with
 *   events[events.length - 1]. Both return { error, message } on failure.
 *
 * Owner: Rida
 */

'use strict';

const path = require('path');

const engineDir = path.join(__dirname, '../engine');

// ── Hareem's engine functions ────────────────────────────────────────────────
const { parseImport }    = require(path.join(engineDir, 'importer'));
const { dedupe }         = require(path.join(engineDir, 'dedupe'));
const { scoreFinding }   = require(path.join(engineDir, 'score'));

// ── Easha's engine functions ─────────────────────────────────────────────────
const { calcSla }        = require(path.join(engineDir, 'sla'));
const { assignOwner }    = require(path.join(engineDir, 'owner'));
const { changeStatus }   = require(path.join(engineDir, 'workflow'));
const { handleRetest }   = require(path.join(engineDir, 'retest'));
const { computeMetrics } = require(path.join(engineDir, 'metrics'));

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

module.exports = { parseImport, dedupe, scoreFinding, buildScoreConfig, calcSla, assignOwner, changeStatus, handleRetest, computeMetrics };
