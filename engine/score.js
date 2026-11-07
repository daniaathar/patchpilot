/**
 * engine/score.js
 * FR-3 Scoring: Calculates a priority score and human-readable reasons for each finding.
 * Owner: Hareem
 *
 * scoreFinding(finding, config) ->
 *   { score, priority, reasons: [...], ruleVersion }
 *
 * Default formula (from project spec, page 3):
 *   score = (cvss * cvssMultiplier)
 *         + assetPoints[assetCriticality]
 *         + (internetFacing ? internetFacingBonus : 0)
 *   Capped at 100.
 *
 * Priority bands:
 *   >= 80 → Critical
 *   60–79 → High
 *   40–59 → Medium
 *   < 40  → Low
 */

'use strict';

// Default scoring weights – admin can override via config
const DEFAULT_CONFIG = {
  cvssMultiplier: 6,          // CVSS score is multiplied by this
  assetPoints: {
    low: 0,
    medium: 10,
    high: 20,
    critical: 30
  },
  internetFacingBonus: 10,    // Added if the asset is internet-facing
  maxScore: 100,
  priorityBands: {            // Lower bound (inclusive) for each band
    critical: 80,
    high: 60,
    medium: 40
    // anything below medium threshold = Low
  },
  ruleVersion: 'v1'
};

/**
 * Merges caller-supplied config on top of defaults.
 * Allows partial overrides (e.g. only change cvssMultiplier).
 */
function mergeConfig(config) {
  if (!config) return DEFAULT_CONFIG;
  return {
    cvssMultiplier: config.cvssMultiplier ?? DEFAULT_CONFIG.cvssMultiplier,
    assetPoints: Object.assign({}, DEFAULT_CONFIG.assetPoints, config.assetPoints),
    internetFacingBonus: config.internetFacingBonus ?? DEFAULT_CONFIG.internetFacingBonus,
    maxScore: config.maxScore ?? DEFAULT_CONFIG.maxScore,
    priorityBands: Object.assign({}, DEFAULT_CONFIG.priorityBands, config.priorityBands),
    ruleVersion: config.ruleVersion ?? DEFAULT_CONFIG.ruleVersion
  };
}

/**
 * Determines the priority label from a numeric score.
 */
function getPriority(score, bands) {
  if (score >= bands.critical) return 'Critical';
  if (score >= bands.high)     return 'High';
  if (score >= bands.medium)   return 'Medium';
  return 'Low';
}

/**
 * scoreFinding(finding, config)
 *
 * Scores a single finding and returns the score, priority label, and
 * a list of plain-English reasons explaining every point added.
 *
 * @param {Finding} finding - The finding object to score
 * @param {object}  config  - Optional config overrides (uses defaults if omitted)
 * @returns {{ score: number, priority: string, reasons: string[], ruleVersion: string }}
 */
function scoreFinding(finding, config) {
  const cfg = mergeConfig(config);
  const reasons = [];

  // --- CVSS contribution ---
  const cvss = parseFloat(finding.cvss);
  if (isNaN(cvss) || cvss < 0 || cvss > 10) {
    throw new Error(`Invalid cvss value: '${finding.cvss}'. Must be 0–10.`);
  }
  const cvssPoints = parseFloat((cvss * cfg.cvssMultiplier).toFixed(1));
  reasons.push(`CVSS ${cvss} gives ${cvssPoints} points (${cvss} × ${cfg.cvssMultiplier}).`);

  // --- Asset criticality contribution ---
  const criticality = String(finding.assetCriticality || '').toLowerCase().trim();
  const assetPts = cfg.assetPoints[criticality];
  if (assetPts === undefined) {
    throw new Error(`Unknown assetCriticality: '${finding.assetCriticality}'. Must be low, medium, high, or critical.`);
  }
  if (assetPts > 0) {
    reasons.push(`${capitalise(criticality)} asset adds ${assetPts} points.`);
  } else {
    reasons.push(`${capitalise(criticality)} asset adds 0 points.`);
  }

  // --- Internet-facing contribution ---
  let internetPts = 0;
  if (finding.internetFacing === true || String(finding.internetFacing).toLowerCase() === 'true') {
    internetPts = cfg.internetFacingBonus;
    reasons.push(`Internet-facing asset adds ${internetPts} points.`);
  } else {
    reasons.push('Asset is not internet-facing; 0 bonus points.');
  }

  // --- Total and cap ---
  let rawScore = cvssPoints + assetPts + internetPts;
  const capped = rawScore > cfg.maxScore;
  const score = parseFloat(Math.min(rawScore, cfg.maxScore).toFixed(1));

  if (capped) {
    reasons.push(`Raw score ${rawScore} exceeds maximum; capped at ${cfg.maxScore}.`);
  }

  const priority = getPriority(score, cfg.priorityBands);
  reasons.push(`Total ${score} means ${priority} (rule ${cfg.ruleVersion}).`);

  return { score, priority, reasons, ruleVersion: cfg.ruleVersion };
}

/** Capitalises the first letter of a string. */
function capitalise(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

module.exports = { scoreFinding, DEFAULT_CONFIG };
