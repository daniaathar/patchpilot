'use strict';
const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const request = require('supertest');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'patchpilot-final-'));
process.env.PATCHPILOT_DB=path.join(dir,'test.db');
process.env.PATCHPILOT_ALLOW_REGISTRATION='1';
const app=require('../server/app');
const {getDb}=require('../server/db');
const bcrypt=require('bcrypt');
let admin, analyst, viewer, aToken, nToken, vToken, id;
async function login(username,password){
 const agent=request.agent(app);
 const r=await agent.post('/api/login').send({username,password}); assert.equal(r.status,200);
 const t=await agent.get('/api/csrf-token'); assert.equal(t.status,200); return [agent,t.body.csrfToken];
}
before(async()=>{
 [admin,aToken]=await login('admin','Admin@1234');
 [analyst,nToken]=await login('analyst','Analyst@1234');
 [viewer,vToken]=await login('viewer','Viewer@1234');
 const r=await analyst.post('/api/import').set('X-CSRF-Token',nToken).attach('file',path.join(__dirname,'../fixtures/sample_good.csv'));
 assert.equal(r.status,200); assert.equal(r.body.inserted,17); assert.equal(r.body.duplicateDetails.length,3);
 id=(await analyst.get('/api/findings')).body[0].id;
});
after(()=>{getDb().close();fs.rmSync(dir,{recursive:true,force:true});});
function status(agent,token,id,action,extra={}){return agent.post(`/api/findings/${id}/status`).set('X-CSRF-Token',token).send({action,...extra});}
function retest(agent,token,id,result){return agent.post(`/api/findings/${id}/retest`).set('X-CSRF-Token',token).send({result,evidence:'Synthetic verification evidence'});}
test('server enforces pending verification, reopening and verified date persistence',async()=>{
 assert.equal((await retest(analyst,nToken,id,'pass')).status,400);
 assert.equal((await status(viewer,vToken,id,'start_work')).status,403);
 assert.equal((await status(analyst,nToken,id,'start_work')).status,200);
 const pending=await status(analyst,nToken,id,'mark_fixed'); assert.equal(pending.status,200); assert.equal(pending.body.finding.status,'awaiting_retest');
 assert.equal((await analyst.get('/api/metrics')).body.open,17);
 const fail=await retest(analyst,nToken,id,'fail'); assert.equal(fail.status,200); assert.equal(fail.body.status,'reopened');
 assert.ok(getDb().prepare('SELECT slaStart FROM findings WHERE id=?').get(id).slaStart);
 assert.equal((await status(analyst,nToken,id,'start_work')).status,200);
 assert.equal((await status(analyst,nToken,id,'mark_fixed')).status,200);
 assert.equal((await retest(analyst,nToken,id,'pass')).status,200);
 assert.ok(getDb().prepare('SELECT fixedAt FROM findings WHERE id=?').get(id).fixedAt);
 assert.equal((await analyst.get('/api/metrics')).body.fixed,1);
 assert.equal((await retest(analyst,nToken,id,'pass')).status,400);
});
test('risk acceptance expiry persists and expired risk reopens',async()=>{
 const f=(await analyst.get('/api/findings')).body.find(x=>x.status==='open');
 assert.equal((await status(analyst,nToken,f.id,'accept_risk',{reason:'Synthetic test',endDate:'2099-01-01'})).status,403);
 assert.equal((await status(admin,aToken,f.id,'accept_risk',{reason:'Synthetic test',endDate:'2099-01-01'})).status,200);
 assert.equal(getDb().prepare('SELECT endDate FROM findings WHERE id=?').get(f.id).endDate,'2099-01-01');
 getDb().prepare('UPDATE findings SET endDate=? WHERE id=?').run('2000-01-01',f.id);
 assert.equal((await admin.get(`/api/findings/${f.id}`)).body.status,'reopened');
});
test('scoring snapshot is reproducible and viewer cannot see it',async()=>{
 const f=(await analyst.get('/api/findings')).body.find(x=>x.status==='open');
 const {scoreFinding}=require('../engine/score'); assert.equal(scoreFinding(f,f.scoreConfig).score,f.priorityScore);
 assert.equal((await viewer.get(`/api/findings/${f.id}`)).body.scoreConfig,undefined);
 const r=await admin.put('/api/config').set('X-CSRF-Token',aToken).send({cvssMultiplier:5}); assert.equal(r.status,200);
 const changed=(await analyst.get(`/api/findings/${f.id}`)).body; assert.equal(changed.scoreConfig.cvssMultiplier,5);
 assert.equal(scoreFinding(changed,changed.scoreConfig).score,changed.priorityScore);
 assert.ok(changed.history.some(x=>x.action==='score_recalculated'&&x.previousConfig.cvssMultiplier===6));
});
test('registration requires CSRF, rejects role and weak password, hashes passwords, blocks duplicates',async()=>{
 const guest=request.agent(app);const username='evaluation-user',password='SyntheticPass123!';
 assert.equal((await guest.post('/api/register').send({username,password})).status,403);
 const token=(await guest.get('/api/csrf-token')).body.csrfToken;
 const register=body=>guest.post('/api/register').set('X-CSRF-Token',token).send(body);
 assert.equal((await register({username,password,role:'admin'})).status,400);
 assert.equal((await register({username,password:'short'})).status,400);
 const success=await register({username,password});assert.equal(success.status,201);assert.equal(success.body.role,'viewer');
 const row=getDb().prepare('SELECT * FROM users WHERE username=?').get(username);assert.equal(row.role,'viewer');assert.notEqual(row.password_hash,password);assert.ok(await bcrypt.compare(password,row.password_hash));
 assert.equal((await register({username,password})).status,409);
 process.env.PATCHPILOT_ALLOW_REGISTRATION='0';
 assert.equal((await register({username:'blocked-user',password})).status,403);
});
