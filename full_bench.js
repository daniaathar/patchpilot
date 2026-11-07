const { scoreFinding } = require('./engine/score');
const { calcSla } = require('./engine/sla');
const { assignOwner } = require('./engine/owner');
const { computeMetrics } = require('./engine/metrics');

const criticalities = ['low','medium','high','critical'];
const prefixes = ['web-','db-','app-','net-','win-','api-','file-','unknown-'];
const statuses = ['open','in_progress','reopened'];

const findings = [];
for (let i = 0; i < 1000; i++) {
  findings.push({
    id: 'F-' + i,
    cve: 'CVE-2024-' + (1000 + i),
    cvss: Math.round((Math.random() * 10) * 10) / 10,
    asset: prefixes[i % prefixes.length] + i,
    assetCriticality: criticalities[i % 4],
    internetFacing: i % 3 === 0,
    firstSeen: '2026-10-01',
    status: statuses[i % statuses.length]
  });
}

const now = '2026-11-07T12:00:00Z';

const start = process.hrtime.bigint();
for (const f of findings) {
  const scored = scoreFinding(f);
  f.score = scored.score;
  f.priority = scored.priority;

  const sla = calcSla(f, {}, now);
  f.dueDate = sla.dueDate;
  f.overdue = sla.overdue;

  const ownerResult = assignOwner(f);
  f.owner = ownerResult.owner;
}
const metrics = computeMetrics(findings, now);
const end = process.hrtime.bigint();

console.log('Full pipeline (score + SLA + owner + metrics) for', findings.length, 'findings:', (Number(end - start) / 1e6).toFixed(2), 'ms');
console.log('Sample metrics ->', JSON.stringify(metrics, null, 2));
