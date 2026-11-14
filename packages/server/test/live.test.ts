// Live output and the ways secrets are kept out of it (and out of saved output).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { sensitiveValues, hideValues } from '../src/sensitive.ts';
import { Scrubber, LiveLogs } from '../src/live.ts';
import { checkExtraArgs, safeVarFile } from '../src/commands.ts';
import { renderOutputs, toolEnv } from '../src/runner.ts';
import { scanSecrets } from '../src/secrets.ts';
import { addSecret, redact } from '../src/log.ts';

const fixture = (f: string) => readFileSync(join(import.meta.dirname, 'fixtures', f), 'utf-8');

test('sensitive values from real Terraform JSON: state and plan, whatever the attribute is called', () => {
  const state = sensitiveValues(JSON.parse(fixture('state-sensitive.json')));
  assert.ok(state.includes('hunter2-SUPERSECRET'), 'from the marked input and the sensitive output');
  assert.ok(!state.includes('admin'), 'unmarked values are left alone');
  const plan = sensitiveValues(JSON.parse(fixture('plan-sensitive.json')));
  assert.ok(plan.includes('hunter2-SUPERSECRET'));
  // Terraform's own plan text prints it, under an attribute that isn't marked sensitive.
  const text = fixture('plan-sensitive.txt');
  assert.match(text, /hunter2-SUPERSECRET/);
  const hidden = hideValues(text, plan);
  assert.doesNotMatch(hidden, /hunter2-SUPERSECRET/);
  assert.match(hidden, /password = "\(sensitive value\)"/);
});

test('scrubber: a secret split across chunks is still caught, line by line', () => {
  const live = new LiveLogs();
  const w = live.start(1, 'r#1|p', { mode: 'redact', patterns: [] });
  const got: string[] = [];
  live.subscribe(1, lines => got.push(...lines));
  w.write('  + tags = { key = "AKIA');
  w.write('IOSFODNN7EXAMPLE" }\nnext li');
  w.write('ne\n');
  w.end();
  assert.deepEqual(got, ['  + tags = { key = "‹redacted: aws-access-key›" }', 'next line']);
  assert.deepEqual(w.found(), ['aws-access-key']);
});

test('scrubber: private keys across lines, bare key lines, sensitive values, server secrets', () => {
  addSecret('server-only-secret-value');
  const s = new Scrubber({ mode: 'redact', patterns: [] });
  s.addSensitive(['hunter2-SUPERSECRET']);
  const out = [
    'before',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA7bodyline',
    'more body',
    '-----END RSA PRIVATE KEY-----',
    'A'.repeat(64),
    'password = "hunter2-SUPERSECRET"',
    'token server-only-secret-value here',
    'after',
  ].map(l => s.line(l)).filter(l => l !== null);
  assert.deepEqual(out, ['before', '‹redacted: private-key›', '‹redacted: private-key›', 'password = "(sensitive value)"', 'token *** here', 'after']);
});

test('scrubber: "fail" mode stops the stream at the first secret; "off" only hides known values', () => {
  const fail = new Scrubber({ mode: 'fail', patterns: [] });
  assert.equal(fail.line('ok'), 'ok');
  assert.match(fail.line('ghp_' + 'a'.repeat(36))!, /the rest of this output is withheld/);
  assert.equal(fail.line('anything after'), null);
  const off = new Scrubber({ mode: 'off', patterns: [] });
  off.addSensitive(['hunter2-SUPERSECRET']);
  assert.equal(off.line('ghp_' + 'a'.repeat(36)), 'ghp_' + 'a'.repeat(36), 'patterns are off');
  assert.equal(off.line('x hunter2-SUPERSECRET'), 'x (sensitive value)', 'Terraform-sensitive values are always hidden');
  const custom = new Scrubber({ mode: 'redact', patterns: [{ name: 'acme', regex: 'acme_[0-9]{6}' }] });
  assert.equal(custom.line('id acme_123456'), 'id ‹redacted: acme›');
});

test('live logs: late viewers get the backlog; done; a PR or one project can be dropped', () => {
  const live = new LiveLogs();
  const w = live.start(7, 'github.com/a/b#3|infra/dev', { mode: 'redact', patterns: [] });
  w.write('one\ntwo\n');
  const seen: string[] = [];
  let done = false;
  const sub = live.subscribe(7, (lines, d) => { seen.push(...lines); done ||= d; })!;
  assert.deepEqual(sub.backlog, ['one', 'two']);
  w.write('three\n');
  w.end();
  assert.deepEqual([seen, done], [['three'], true]);
  assert.equal(live.subscribe(7, () => {})!.done, true, 'kept a while after the end');
  live.start(8, 'github.com/a/b#3|infra/prod', { mode: 'redact', patterns: [] });
  live.dropPr('github.com/a/b#3', 'infra/dev');
  assert.deepEqual([live.has(7), live.has(8)], [false, true], 'one project');
  live.dropPr('github.com/a/b#3');
  assert.equal(live.has(8), false, 'the whole PR');
  assert.equal(live.subscribe(99, () => {}), null);
});

test('extra plan arguments: allowlisted flags; -var-file stays inside the repo', () => {
  assert.equal(checkExtraArgs(['-var', 'a=1', '-var-file=env/prod.tfvars', '-target', 'x.y', '-compact-warnings']), null);
  for (const bad of [['-chdir=/'], ['-state=/tmp/x'], ['-out=/tmp/p'], ['-plugin-dir', '/x'], ['-json']]) {
    assert.match(checkExtraArgs(bad)!, /isn't allowed after `--`/, bad.join(' '));
  }
  for (const f of ['/secrets/github/private-key', '../../etc/passwd', '~/x', 'a/../../b', 'C:\\x']) {
    assert.match(checkExtraArgs([`-var-file=${f}`])!, /must be a path inside the repo/, f);
  }
  assert.match(checkExtraArgs(['oops'])!, /isn't a flag/);
  assert.ok(safeVarFile('vars/prod.tfvars'));
});

test('outputs: sensitive ones never printed, even by name', () => {
  const json = JSON.stringify({ password: { sensitive: true, value: 'hunter2-SUPERSECRET' }, user: { sensitive: false, value: 'admin' }, list: { value: ['a', 'b'] } });
  assert.equal(renderOutputs(json, 'password').text, 'password = (sensitive value)');
  assert.equal(renderOutputs(json, 'user').text, 'user = "admin"');
  assert.doesNotMatch(renderOutputs(json).text, /hunter2/);
  assert.equal(renderOutputs(json, 'nope').ok, false);
});

test('Terraform never gets TF_LOG (debug logs print credentials)', () => {
  const env = toolEnv({ TF_LOG: 'TRACE', TF_LOG_PATH: '/tmp/x', TF_LOG_PROVIDER: 'DEBUG', TERIAC_API_TOKEN: 's', AWS_REGION: 'eu-west-1' }, {});
  assert.deepEqual([env.TF_LOG, env.TF_LOG_PATH, env.TF_LOG_PROVIDER, env.TERIAC_API_TOKEN, env.AWS_REGION], [undefined, undefined, undefined, undefined, 'eu-west-1']);
});

test('secret patterns: half a key, URL and connection-string passwords, more token formats', () => {
  const cases: [string, string][] = [
    ['-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'private-key'],
    ['MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----', 'private-key'],
    ['url = "postgres://app:S3cretPass@db.internal:5432/app"', 'url-password'],
    ['Server=db;Database=app;User Id=sa;Password=S3cretPass;', 'connection-string-password'],
    ['VAULT_TOKEN=hvs.CAESIabcdefghijklmnopqrstuvwxyz012345', 'vault-token'],
    [`token = "abcdefghijklmn.atlasv1.${'x'.repeat(64)}"`, 'terraform-cloud-token'],
    [`key sk-ant-${'a'.repeat(40)}`, 'anthropic-key'],
    ['  + client_secret = "very-secret-value"', 'password'],
    ['  + db_token = "abcdefghij"', 'password'],
  ];
  for (const [text, kind] of cases) {
    const r = scanSecrets(text);
    assert.ok(r.found.includes(kind), `${kind}: ${text}`);
  }
  assert.doesNotMatch(scanSecrets('url = "postgres://app:S3cretPass@db"').text, /S3cretPass/);
  assert.deepEqual(scanSecrets('  + token_type = "Bearer"\n  + password = (sensitive value)\n  + name = "web"').found, [], 'no false alarms on ordinary lines');
});

test('a multi-line server secret is hidden line by line (e.g. one line quoted in an error)', () => {
  addSecret('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAuniquekeyline0123456789\n-----END RSA PRIVATE KEY-----');
  assert.equal(redact('  1: MIIEowIBAAKCAQEAuniquekeyline0123456789'), '  1: ***');
});

test('live endpoint: needs sign-in; backlog, new lines as they come, then done', async () => {
  const { createHttpServer } = await import('../src/http.ts');
  const { Store } = await import('../src/store.ts');
  const store = new Store(':memory:');
  const id = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'envs/dev', workspace: 'default', kind: 'plan', headSha: 'abc', user: 'bob' });
  const live = new LiveLogs();
  const w = live.start(id, 'github.com/acme/infra#1|envs/dev', { mode: 'redact', patterns: [] });
  w.write('$ terraform plan\nRefreshing state...\n');
  const auth = { apiToken: 'api-token-for-tests-1234567890', sessionSecret: 's'.repeat(32), sessionHours: 1, secureCookies: false, users: [] } as any;
  const srv = createHttpServer({ app: { runQueue: null, live } as any, store, adapters: {}, auth, ready: () => true });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(srv.address() as import('node:net').AddressInfo).port}`;
  assert.equal((await fetch(`${base}/api/runs/${id}/live`)).status, 401);
  const res = await fetch(`${base}/api/runs/${id}/live`, { headers: { Authorization: `Bearer ${auth.apiToken}` } });
  assert.equal(res.headers.get('content-type'), 'text/event-stream');
  const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
  let text = '';
  const until = async (re: RegExp) => { while (!re.test(text)) { const { value, done } = await reader.read(); if (done) break; text += value; } };
  await until(/Refreshing state/);
  assert.match(text, /event: lines\ndata: \["\$ terraform plan","Refreshing state\.\.\."\]/);
  w.write('  + key = "ghp_' + 'a'.repeat(36) + '"\n');
  await until(/redacted/);
  assert.doesNotMatch(text, /ghp_a/);
  w.end();
  await until(/event: done/);
  // A finished run's saved log is on the run page; the live endpoint just says done.
  const old = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'envs/prod', workspace: 'default', kind: 'plan', headSha: 'abc', user: 'bob' });
  assert.match(await (await fetch(`${base}/api/runs/${old}/live`, { headers: { Authorization: `Bearer ${auth.apiToken}` } })).text(), /event: done\ndata: \{"saved":true\}/);
  assert.equal((await fetch(`${base}/api/runs/99999/live`, { headers: { Authorization: `Bearer ${auth.apiToken}` } })).status, 404);
  srv.close();
  store.close();
});

test('a repo entry can add its own secret patterns to the server-wide ones', async () => {
  const { parseServerPolicy } = await import('../src/config.ts');
  const p = parseServerPolicy(`
secret_scan:
  patterns: [{ name: server-token, regex: "srv_[0-9]{6}" }]
repos:
  - id: github.com/acme/infra
    secret_scan:
      mode: fail
      patterns: [{ name: acme-token, regex: "acme_[0-9]{6}" }]
  - id: github.com/acme/*
    secret_scan: redact
`);
  assert.deepEqual([p.repos[0].secret_scan, p.repos[0].secret_patterns!.map(x => x.name)], ['fail', ['acme-token']]);
  assert.deepEqual([p.repos[1].secret_scan, p.repos[1].secret_patterns], ['redact', []]);
  assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    secret_scan: { patterns: [{ name: x, regex: "(" }] }\n'), /patterns\[0\]\.regex/);
});

test('live endpoint: a viewer who connects before output starts still gets it', async () => {
  const { createHttpServer } = await import('../src/http.ts');
  const { Store } = await import('../src/store.ts');
  const store = new Store(':memory:');
  const id = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'envs/dev', workspace: 'default', kind: 'plan', headSha: 'abc', user: 'bob' });
  const live = new LiveLogs();
  const auth = { apiToken: 'api-token-for-tests-1234567890', sessionSecret: 's'.repeat(32), sessionHours: 1, secureCookies: false, users: [] } as any;
  const srv = createHttpServer({ app: { runQueue: null, live } as any, store, adapters: {}, auth, ready: () => true });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
  const base = `http://127.0.0.1:${(srv.address() as import('node:net').AddressInfo).port}`;
  const body = fetch(`${base}/api/runs/${id}/live`, { headers: { Authorization: `Bearer ${auth.apiToken}` } }).then(r => r.text());
  await new Promise(r => setTimeout(r, 400));
  const w = live.start(id, 'github.com/acme/infra#1|envs/dev', { mode: 'redact', patterns: [] });
  w.write('$ terraform init\n');
  w.end();
  const text = await body;
  assert.match(text, /event: lines\ndata: \["\$ terraform init"\]/);
  assert.match(text, /event: done/);
  srv.close();
  store.close();
});
