/**
 * engine/dedupe.js
 * FR-2 Deduplication: Removes duplicate findings based on CVE + asset key.
 * Owner: Hareem
 *
 * dedupe(newList, existingList) ->
 *   { unique: [findings], duplicates: [{finding, matchedId, reason}] }
 */

'use strict';

/**
 * Builds the deduplication key for a finding.
 * Key = lowercase(cve) + '::' + lowercase(asset)
 * This ensures CVE-2024-1111 on web-01 is always the same key regardless of case.
 */
function dedupKey(finding) {
  const cve = String(finding.cve || '').toLowerCase().trim();
  const asset = String(finding.asset || '').toLowerCase().trim();
  return `${cve}::${asset}`;
}

/**
 * Picks the earlier of two ISO date strings (YYYY-MM-DD or ISO timestamp).
 * Returns the string that represents the older date.
 */
function earlierDate(dateA, dateB) {
  if (!dateA) return dateB;
  if (!dateB) return dateA;
  return new Date(dateA) <= new Date(dateB) ? dateA : dateB;
}

/**
 * dedupe(newList, existingList)
 *
 * Compares incoming findings against an existing list.
 * A finding is a duplicate if the same CVE appears on the same asset (case-insensitive).
 * When a duplicate is found, the existing record is kept and firstSeen is preserved
 * as the oldest of the two dates.
 *
 * @param {Finding[]} newList      - Findings from the current import
 * @param {Finding[]} existingList - Findings already in the system (may be empty)
 * @returns {{
 *   unique: Finding[],
 *   duplicates: { finding: Finding, matchedId: string|null, reason: string }[]
 * }}
 */
function dedupe(newList, existingList) {
  const unique = [];
  const duplicates = [];

  // Build a lookup map of existing findings keyed by dedupKey -> finding
  const existingMap = new Map();
  for (const f of (existingList || [])) {
    existingMap.set(dedupKey(f), f);
  }

  // Track keys we have already accepted within this batch (intra-batch dedup)
  const acceptedInBatch = new Map(); // key -> finding already accepted in this batch

  for (const finding of (newList || [])) {
    const key = dedupKey(finding);

    // Check against existing list first
    if (existingMap.has(key)) {
      const matched = existingMap.get(key);
      // Keep the oldest firstSeen on the existing record
      matched.firstSeen = earlierDate(matched.firstSeen, finding.firstSeen);
      duplicates.push({
        finding,
        matchedId: matched.id || null,
        reason: `Same ${finding.cve} on ${finding.asset} already exists as ${matched.id || '(existing record)'}.`
      });
      continue;
    }

    // Check for duplicates within the new batch itself
    if (acceptedInBatch.has(key)) {
      const matched = acceptedInBatch.get(key);
      // Keep the oldest firstSeen on the already-accepted record
      matched.firstSeen = earlierDate(matched.firstSeen, finding.firstSeen);
      duplicates.push({
        finding,
        matchedId: matched.id || null,
        reason: `Same ${finding.cve} on ${finding.asset} appears more than once in this import (duplicate of earlier row).`
      });
      continue;
    }

    // Not a duplicate – accept it
    acceptedInBatch.set(key, finding);
    unique.push(finding);
  }

  return { unique, duplicates };
}

module.exports = { dedupe };
