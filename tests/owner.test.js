
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { assignOwner } = require('../engine/owner');

test('Assigns Web Team to web assets', () => {
  const result = assignOwner({ asset: 'web-server-01' });
  assert.equal(result.owner, 'Web Team');
});

test('Assigns Database Team to db assets', () => {
  const result = assignOwner({ asset: 'db-production' });
  assert.equal(result.owner, 'Database Team');
});

test('Assigns App Team to app assets', () => {
  const result = assignOwner({ asset: 'app-mobile' });
  assert.equal(result.owner, 'App Team');
});

test('Assigns Network Team to net assets', () => {
  const result = assignOwner({ asset: 'net-router' });
  assert.equal(result.owner, 'Network Team');
});

test('Assigns Windows Team to win assets', () => {
  const result = assignOwner({ asset: 'win-server' });
  assert.equal(result.owner, 'Windows Team');
});

test('Assigns API Team to api assets', () => {
  const result = assignOwner({ asset: 'api-gateway' });
  assert.equal(result.owner, 'API Team');
});

test('Assigns Storage Team to file assets', () => {
  const result = assignOwner({ asset: 'file-storage' });
  assert.equal(result.owner, 'Storage Team');
});

test('Prefix matching is case-insensitive', () => {
  const result = assignOwner({ asset: 'WEB-server' });
  assert.equal(result.owner, 'Web Team');
});

test('Unknown asset is assigned to Unassigned', () => {
  const result = assignOwner({ asset: 'unknown-server' });
  assert.equal(result.owner, 'Unassigned');
});

test('Custom ownership rules override defaults', () => {
  const result = assignOwner(
    { asset: 'cloud-server' },
    [{ prefix: 'cloud-', owner: 'Cloud Team' }]
  );

  assert.equal(result.owner, 'Cloud Team');
});

test('Returns a reason explaining the assignment', () => {
  const result = assignOwner({ asset: 'web-server' });

  assert.ok(result.reason.includes('web-'));
});

test('Empty asset remains Unassigned', () => {
  const result = assignOwner({});

  assert.equal(result.owner, 'Unassigned');
});

test('Empty custom rules result in Unassigned', () => {
  const result = assignOwner({ asset: 'web-server' }, []);

  assert.equal(result.owner, 'Unassigned');
});
