
'use strict';

const DEFAULT_OWNER_RULES = [
  { prefix: 'web-', owner: 'Web Team' },
  { prefix: 'db-', owner: 'Database Team' },
  { prefix: 'app-', owner: 'App Team' },
  { prefix: 'net-', owner: 'Network Team' },
  { prefix: 'win-', owner: 'Windows Team' },
  { prefix: 'api-', owner: 'API Team' },
  { prefix: 'file-', owner: 'Storage Team' }
];

function assignOwner(finding, ownerRules) {
  if (!finding || typeof finding !== 'object') {
    throw new TypeError('A valid finding object is required.');
  }

  const rules = ownerRules === undefined
    ? DEFAULT_OWNER_RULES
    : ownerRules;

  if (!Array.isArray(rules)) {
    throw new TypeError('Owner rules must be an array.');
  }

  const asset = String(finding.asset || '').trim().toLowerCase();

  for (const rule of rules) {
    if (
      rule &&
      typeof rule.prefix === 'string' &&
      typeof rule.owner === 'string' &&
      rule.prefix.length > 0 &&
      asset.startsWith(rule.prefix.toLowerCase())
    ) {
      return {
        owner: rule.owner,
        reason: `Asset '${finding.asset}' matches prefix '${rule.prefix}'.`
      };
    }
  }

  return {
    owner: 'Unassigned',
    reason: `No ownership rule matched asset '${finding.asset || ''}'.`
  };
}

module.exports = { assignOwner };
