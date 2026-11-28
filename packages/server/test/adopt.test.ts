// teriac adopt: resources made by hand → a PR with import blocks and code, planned first.
// A fake `terraform` writes generated config and reports imports, so no cloud is needed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  parseAdoptArgs, nameFromId, addressesFor, checkAdoptCode, importOutcome, adopt, adoptBody, adoptBranch, generateSupport, topBlocks,
  type AdoptTarget,
} from '../src/adopt.ts';
import { Ai, type AiCall } from '../src/ai.ts';
import { parseCommand, helpText } from '../src/commands.ts';
import { App } from '../src/app.ts';
import { Store } from '../src/store.ts';
import { parseReposYaml } from '../src/config.ts';
import type { ServerConfig } from '../src/config.ts';
import type { Project } from '../src/discovery.ts';
import type { Repo } from '../src/vcs/types.ts';

const FAKE_TF = `#!/usr/bin/env node
const fs = require('fs');
const [cmd, ...rest] = process.argv.slice(2);
const code = () => fs.readdirSync('.').filter(f => f.endsWith('.tf')).map(f => fs.readFileSync(f, 'utf-8')).join('\\n');
if (cmd === 'init') process.exit(0);
if (cmd === 'plan') {
  const out = rest.find(a => a.startsWith('-out=')).slice(5);
  const gen = rest.find(a => a.startsWith('-generate-config-out='));
  if (gen) {
    fs.writeFileSync(gen.split('=')[1], process.env.GEN || '');
    if (process.env.GEN_FAIL) { console.error('Error: Conflicting configuration arguments: "acl" conflicts with "grant"'); process.exit(1); }
  }
  const text = code();
  if (/BROKEN/.test(text)) { console.error('Error: Unsupported argument "BROKEN"'); process.exit(1); }
  fs.writeFileSync(out, text);
  console.log('Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.');
  process.exit(2);
}
if (cmd === 'show' && rest.length === 1) { console.log('{}'); process.exit(0); }
if (cmd === 'show') {
  const text = fs.readFileSync(rest[rest.length - 1], 'utf-8');
  const tos = [...text.matchAll(/^\\s*to\\s*=\\s*(\\S+)/gm)].map(m => m[1]);
  const differs = /DIFFERS/.test(text);
  const changes = tos.map(a => ({ address: a, mode: 'managed', change: { actions: differs ? ['update'] : ['no-op'], before: { acl: 'private' }, after: { acl: differs ? 'public-read' : 'private' }, importing: { id: 'x' } } }));
  if (process.env.OTHER) changes.push({ address: 'aws_sqs_queue.other', mode: 'managed', change: { actions: ['create'], before: null, after: {} } });
  console.log(JSON.stringify({ format_version: '1.2', resource_changes: changes }));
  process.exit(0);
}
process.exit(1);
`;

const GENERATED = `# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "acme-logs"
resource "aws_s3_bucket" "acme_logs" {
  bucket              = "acme-logs"
  bucket_prefix       = null
  force_destroy       = null
  object_lock_enabled = false
  tags                = {}
  tags_all            = {}
}
`;

const CLEAN = `import {
  to = aws_s3_bucket.logs
  id = "acme-logs"
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
}
`;

let tmp: string;
let fakeTf: string;
const project = (dir = 'envs/prod'): Project => ({ name: dir, dir, workspace: 'default', engine: 'terraform', tool: 'terraform', autoplan: true, watch: [], deps: [] });
const tools = () => ({ tool: { provider: 'terraform' as const, version: '1.9.8', binary: fakeTf } });
const targets = (...a: string[]) => { const r = parseAdoptArgs(a); assert.ok(r.ok); return r.targets; };

// A fake Claude answering each request with the next answer in the list.
const fakeAi = (answers: unknown[]) => {
  const sent: string[] = [];
  const call: AiCall = async (params) => {
    sent.push(String((params.messages[0] as any).content));
    const answer = answers[Math.min(sent.length - 1, answers.length - 1)];
    return { id: 'm', type: 'message', role: 'assistant', model: params.model, content: [{ type: 'text', text: JSON.stringify(answer) }], stop_reason: 'end_turn', stop_details: null, usage: { input_tokens: 1, output_tokens: 1 } } as any;
  };
  const ai = new Ai({ provider: 'anthropic', model: 'claude-opus-5-5', effort: 'medium', features: ['import'], timeoutMs: 1000 }, { call });
  return { ai, sent, s: { features: ['import' as const], model: 'claude-opus-5-5', effort: 'medium' as const, review: 'push' as const } };
};

const repoDir = () => {
  const root = mkdtempSync(join(tmp, 'repo-'));
  mkdirSync(join(root, 'envs/prod'), { recursive: true });
  writeFileSync(join(root, 'envs/prod/main.tf'), 'resource "aws_s3_bucket" "assets" {\n  bucket = "acme-assets"\n}\n');
  return root;
};
const run = (root: string, t: AdoptTarget[], env: Record<string, string> = {}, extra: Partial<Parameters<typeof adopt>[0]> = {}) => adopt({
  root, ctx: { root, project: project(), tools: tools(), env: { PATH: process.env.PATH, GEN: GENERATED, ...env }, timeoutMs: 30_000 },
  planDir: join(tmp, 'plans'), targets: t, ...extra,
});

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'teriac-adopt-'));
  fakeTf = join(tmp, 'terraform');
  writeFileSync(fakeTf, FAKE_TF);
  chmodSync(fakeTf, 0o755);
});
after(() => rmSync(tmp, { recursive: true, force: true }));

test('arguments: pairs of type (or type.name) and ID, checked', () => {
  assert.deepEqual(targets('aws_s3_bucket', 'acme-logs', 'aws_iam_role.deploy', 'deploy-bot'), [
    { type: 'aws_s3_bucket', name: null, id: 'acme-logs' }, { type: 'aws_iam_role', name: 'deploy', id: 'deploy-bot' },
  ]);
  for (const [args, error] of [
    [[], /pairs/], [['aws_s3_bucket'], /pairs/], [['S3', 'x'], /not a resource type/], [['aws_s3_bucket.a.b', 'x'], /not a resource type/],
    [['aws_s3_bucket', 'a"b'], /not an import ID/], [['aws_s3_bucket', '${x}'], /not an import ID/], [['aws_s3_bucket', 'x', 'aws_s3_bucket', 'x'], /twice/],
    [Array(42).fill('aws_s3_bucket').map((v, i) => (i % 2 ? `b${i}` : v)), /at most 20/],
  ] as [string[], RegExp][]) {
    const r = parseAdoptArgs(args);
    assert.ok(!r.ok && error.test(r.error), `${args.join(' ')}: ${!r.ok && r.error}`);
  }
});

test('names come from the ID, unique against the project', () => {
  assert.equal(nameFromId('arn:aws:iam::123456789012:role/deploy-bot'), 'deploy_bot');
  assert.equal(nameFromId('vpc-0abc'), 'vpc_0abc');
  assert.equal(nameFromId('123'), 'r_123');
  const r = addressesFor(targets('aws_s3_bucket', 'logs', 'aws_s3_bucket', 'team/logs'), new Set(['aws_s3_bucket.logs']));
  assert.deepEqual(r.map(x => x.address), ['aws_s3_bucket.logs_2', 'aws_s3_bucket.logs_3']);
});

test('generation needs Terraform 1.5 / OpenTofu 1.6, and not Terragrunt yet', () => {
  assert.equal(generateSupport({ tool: { provider: 'terraform', version: '1.5.0', binary: '' } }), null);
  assert.match(generateSupport({ tool: { provider: 'terraform', version: '1.4.6', binary: '' } })!, /Terraform 1.5/);
  assert.match(generateSupport({ tool: { provider: 'opentofu', version: '1.5.9', binary: '' } })!, /OpenTofu 1.6/);
  assert.match(generateSupport({ tool: { provider: 'terraform', version: '1.9.8', binary: '' }, terragrunt: { provider: 'terragrunt', version: '0.70.0', binary: '' } })!, /Terragrunt/);
});

test('the code check: only the asked-for imports and their resources, nothing that runs or reads files', () => {
  const t = targets('aws_s3_bucket', 'acme-logs');
  const ok = checkAdoptCode(CLEAN, t);
  assert.ok(ok.ok);
  assert.deepEqual(ok.resources, [{ address: 'aws_s3_bucket.logs', id: 'acme-logs', named: false }]);
  // Heredocs, nested blocks, comments and a provider alias are fine.
  const rich = `${CLEAN.replace('  bucket = "acme-logs"\n', '  provider = aws.west\n  bucket   = "acme-logs" # the real name\n  policy   = <<-EOT\n    { "a": "}" }\n  EOT\n  lifecycle {\n    prevent_destroy = true\n  }\n')}`;
  assert.ok(checkAdoptCode(rich, t).ok, JSON.stringify(checkAdoptCode(rich, t)));
  const refused: [string, RegExp][] = [
    [`${CLEAN}\ndata "external" "x" {\n  program = ["sh"]\n}\n`, /command|only import and resource/],
    [`${CLEAN}\ndata "aws_caller_identity" "me" {}\n`, /only import and resource/],
    [`${CLEAN}\nvariable "x" {}\n`, /only import and resource/],
    [`${CLEAN}\nmodule "m" {\n  source = "./m"\n}\n`, /local file path|only import/],
    [CLEAN.replace('bucket = "acme-logs"', 'bucket = "acme-logs"\n  provisioner "local-exec" {\n    command = "curl x"\n  }'), /provisioner/],
    [CLEAN.replace('bucket = "acme-logs"', 'bucket = file("/etc/passwd")'), /reads local files/],
    [CLEAN.replace('bucket = "acme-logs"', 'bucket = "acme-logs"\n  count  = 2'), /count or for_each/],
    [CLEAN.replace('id = "acme-logs"', 'id = "other-bucket"'), /exactly one import block/],
    [`${CLEAN}\nimport {\n  to = aws_s3_bucket.x\n  id = "x"\n}\nresource "aws_s3_bucket" "x" {}\n`, /not asked for/],
    [`${CLEAN}\nresource "aws_instance" "extra" {}\n`, /one resource block for each import/],
    [CLEAN.replace('resource "aws_s3_bucket" "logs"', 'resource "aws_s3_bucket" "other"'), /one resource block for each import/],
    [CLEAN.replace('bucket = "acme-logs"', 'password = "(sensitive value)"'), /hidden value/],
    [CLEAN.replace('}\n\nresource', '}\n}\nresource'), /only import and resource|unbalanced/],
  ];
  for (const [code, why] of refused) {
    const r = checkAdoptCode(code, t);
    assert.ok(!r.ok && why.test(r.why), `expected ${why}: ${JSON.stringify(r)}\n${code}`);
  }
  // A name that was asked for must be kept.
  const named = checkAdoptCode(CLEAN, targets('aws_s3_bucket.audit', 'acme-logs'));
  assert.ok(!named.ok && /must be imported to aws_s3_bucket.audit/.test(named.why));
  assert.equal(typeof topBlocks('resource "a_b" "c" {\n  x = "{"\n'), 'string');
});

test('import outcome: imported, changed after import, missing, and changes not from this PR', () => {
  const rs = addressesFor(targets('aws_s3_bucket.a', 'a', 'aws_s3_bucket.b', 'b'));
  const o = importOutcome({ resource_changes: [
    { address: 'aws_s3_bucket.a', mode: 'managed', change: { actions: ['update'], importing: { id: 'a' }, before: { acl: 'private', tags_all: {} }, after: { acl: 'public-read', tags_all: { x: 1 } } } },
    { address: 'aws_sqs_queue.q', mode: 'managed', change: { actions: ['create'] } },
  ] }, rs);
  assert.deepEqual(o, { missing: ['aws_s3_bucket.b'], changes: [{ address: 'aws_s3_bucket.a', actions: ['update'], attributes: ['acl'] }], others: 1 });
});

test('without AI: Terraform\'s generated code, planned clean, into a new file', async () => {
  const root = repoDir();
  const r = await run(root, targets('aws_s3_bucket', 'acme-logs'));
  assert.ok(r.ok, r.error ?? '');
  assert.equal(r.file!.path, 'envs/prod/imported-s3-bucket.tf');
  assert.match(r.file!.content, /^import \{\n  to = aws_s3_bucket\.acme_logs\n  id = "acme-logs"\n\}/);
  assert.match(r.file!.content, /resource "aws_s3_bucket" "acme_logs"/);
  assert.doesNotMatch(r.file!.content, /Please review/);
  assert.equal(r.model, undefined);
  assert.deepEqual(r.changes, []);
  // Nothing is left behind in the checkout.
  assert.deepEqual(readdirSync(join(root, 'envs/prod')), ['main.tf']);
  const body = adoptBody('envs/prod', 'main', r, { user: 'bob', from: '#12' });
  assert.match(body, /asked by bob in #12/);
  assert.match(body, /applying imports it and changes nothing/);
  assert.match(body, /Tidy it before merging/);
  assert.equal(adoptBranch('envs/prod', r.resources), 'teriac/adopt/envs_prod-aws_s3_bucket-acme_logs');
});

test('without AI, generated code that does not plan is not turned into a PR', async () => {
  const r = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), { GEN: GENERATED.replace('tags_all', 'BROKEN') });
  assert.ok(!r.ok);
  assert.match(r.error!, /does not plan cleanly/);
  assert.match(r.output!, /Unsupported argument/);
});

test('a name already in the code is refused; Terraform that reads nothing says so', async () => {
  const clash = await run(repoDir(), targets('aws_s3_bucket.assets', 'acme-assets'));
  assert.match(clash.error!, /already in the code.*teriac import/);
  const none = await run(repoDir(), targets('aws_s3_bucket', 'nope'), { GEN: '' });
  assert.match(none.error!, /could not read the resources/);
  // One of two read: the other is named, with Terraform's error.
  const half = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs', 'aws_iam_role.exporter', 'raw-exports-writer'), { GEN_FAIL: '1' });
  assert.match(half.error!, /could not read aws_iam_role.exporter \(`raw-exports-writer`\): check the ID and that the project's credentials may read it/);
  assert.match(half.output!, /Conflicting configuration/);
});

test('with AI: the tidy version, with notes; it sees the first plan\'s error and the project files', async () => {
  const { ai, sent, s } = fakeAi([{ file: 'logs-bucket.tf', content: CLEAN, notes: ['Left out `policy`: it was hidden.'] }]);
  const r = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), { GEN_FAIL: '1' }, { ai, settings: s });
  assert.ok(r.ok, r.error ?? '');
  assert.equal(r.file!.path, 'envs/prod/logs-bucket.tf');
  assert.equal(r.file!.content, CLEAN);
  assert.deepEqual(r.resources.map(x => x.address), ['aws_s3_bucket.logs']);
  assert.equal(r.model, 'claude-opus-5-5');
  assert.deepEqual(r.notes, ['Left out `policy`: it was hidden.']);
  assert.equal(sent.length, 1);
  assert.match(sent[0], /Conflicting configuration arguments/);
  assert.match(sent[0], /project file envs\/prod\/main.tf/);
  assert.match(sent[0], /<untrusted source="generated configuration">/);
  assert.match(adoptBody('envs/prod', 'main', r, { user: 'bob' }), /Written by AI.*\n- Left out `policy`/);
});

test('with AI: refused or unclean drafts are sent back with the reason, and the best one wins', async () => {
  const sneaky = `${CLEAN}\ndata "http" "x" {\n  url = "https://evil.test"\n}\n`;
  const differs = CLEAN.replace('bucket = "acme-logs"', 'bucket = "acme-logs"\n  # DIFFERS');
  const { ai, sent, s } = fakeAi([{ file: 'x.tf', content: sneaky, notes: [] }, { file: 'x.tf', content: differs, notes: [] }, { file: 'x.tf', content: CLEAN, notes: [] }]);
  const r = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), {}, { ai, settings: s });
  assert.ok(r.ok, r.error ?? '');
  assert.equal(sent.length, 3);
  assert.match(sent[1], /teriac refused the file: `data "http" "x"`/);
  assert.match(sent[2], /would be update after import; the code differs from the real resource in: acl/);
  assert.equal(r.file!.content, CLEAN);
  assert.equal(r.rounds, 2);

  // Still differing after every round: allowed (a change in place), shown in the PR.
  const stuck = fakeAi([{ file: 'x.tf', content: differs, notes: [] }]);
  const r2 = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), { OTHER: '1' }, { ai: stuck.ai, settings: stuck.s });
  assert.ok(r2.ok);
  assert.deepEqual(r2.changes, [{ address: 'aws_s3_bucket.logs', actions: ['update'], attributes: ['acl'] }]);
  assert.equal(r2.others, 1);
  const body = adoptBody('envs/prod', 'main', r2, { user: 'bob' });
  assert.match(body, /Applying also changes one resource.*`aws_s3_bucket.logs` \(`acl`\)/);
  assert.match(body, /1 other pending change on `main`/);

  // Never acceptable: nothing to open a PR with.
  const bad = fakeAi([{ file: 'x.tf', content: sneaky, notes: [] }]);
  const r3 = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), {}, { ai: bad.ai, settings: bad.s });
  assert.ok(!r3.ok);
  assert.match(r3.error!, /teriac refused the file/);
});

test('with AI: a secret in the code means no PR', async () => {
  const leaky = CLEAN.replace('bucket = "acme-logs"', 'bucket = "acme-logs"\n  tags   = { key = "AKIAIOSFODNN7EXAMPLE" }');
  const { ai, s } = fakeAi([{ file: 'x.tf', content: leaky, notes: [] }]);
  const r = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), {}, { ai, settings: s });
  assert.ok(!r.ok);
  assert.match(r.error!, /looks like a secret \(aws-access-key\)/);
});

test('the command: `teriac adopt -p <project> <type> <id>...`', () => {
  const ok = parseCommand('teriac adopt -p envs/prod aws_s3_bucket acme-logs aws_iam_role.deploy deploy-bot', ['teriac']);
  assert.ok(ok?.ok);
  assert.deepEqual(ok.command.adopt, targets('aws_s3_bucket', 'acme-logs', 'aws_iam_role.deploy', 'deploy-bot'));
  assert.equal(ok.command.project, 'envs/prod');
  for (const [text, error] of [
    ['teriac adopt aws_s3_bucket x', /writes code for one project/],
    ['teriac adopt -p envs/prod', /Give pairs/],
    ['teriac adopt -p envs/prod aws_s3_bucket x -t a.b', /Only `-p`, `-d` and `-w`/],
    ['teriac adopt -p envs/prod aws_s3_bucket', /Give pairs/],
  ] as [string, RegExp][]) {
    const r = parseCommand(text, ['teriac']);
    assert.ok(r && !r.ok && error.test(r.error), `${text}: ${r && !r.ok && r.error}`);
  }
  assert.match(helpText('teriac', false, true, true), /adopt -p <project> <type> <id>.*written by AI/);
  assert.doesNotMatch(helpText('teriac'), /written by AI/);
});

test('server: permission, a PR against the base branch, audit; a second request finds the branch open', async () => {
  const origin = join(tmp, 'origin');
  mkdirSync(join(origin, 'envs/prod'), { recursive: true });
  writeFileSync(join(origin, 'envs/prod/main.tf'), 'resource "aws_s3_bucket" "assets" {\n  bucket = "acme-assets"\n}\n');
  const git = (...a: string[]) => execFileSync('git', a, { cwd: origin, encoding: 'utf-8' });
  git('init', '-q', '-b', 'main');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '.');
  git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
  git('config', 'uploadpack.allowFilter', 'true');

  const config: ServerConfig = {
    port: 0, dataDir: join(tmp, 'data'), publicUrl: 'https://teriac.example.com', parallelism: 2, runTimeoutMs: 60_000,
    commandNames: ['teriac'], defaultVersion: 'latest', requireApplyProject: false, ackReaction: 'eyes', progressReply: false, commentMode: 'new', spinnerUrl: null,
    auth: { sessionSecret: 'x'.repeat(32), sessionHours: 1, secureCookies: false, users: [] }, channels: {}, people: [],
    repos: parseReposYaml('repos:\n  - id: github.com/acme/*\n    projects:\n      - match: envs/prod\n        permissions:\n          adopt: [team:platform]\n'),
  };
  const store = new Store(':memory:');
  const opened: any[] = [];
  const adapter: any = {
    platform: 'github',
    cloneAuth: async () => ({ url: origin }),
    userPermission: async (_r: Repo, u: string) => (u === 'carol' || u === 'bob' ? 'write' : 'none'),
    inTeam: async (_r: Repo, t: string, u: string) => t === 'platform' && u === 'carol',
    codeowners: async () => null,
    openPullRequest: async (_r: Repo, p: any) => { opened.push(p); return opened.length === 1 ? 'https://github.com/acme/infra/pull/90' : null; },
  };
  const app = new App({ config, store, resolver: { resolve: async () => tools() }, env: { PATH: process.env.PATH!, GEN: GENERATED, TERIAC_GITHUB_PRIVATE_KEY: 'nope' } });
  const repo: Repo = { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '' };
  const policy = config.repos[0];
  const req = (user: string | null) => app.adoptResources({ adapter, repo, policy, base: 'main', select: { project: 'envs/prod' }, targets: targets('aws_s3_bucket', 'acme-logs'), user, from: '#12' });

  const denied = await req('bob');
  assert.ok(!denied.ok);
  assert.match(denied.message, /🚫 `adopt` on `envs\/prod`/);
  assert.equal(opened.length, 0);

  const r = await req('carol');
  assert.ok(r.ok, r.message);
  assert.match(r.message, /✅ Opened https:\/\/github.com\/acme\/infra\/pull\/90: `envs\/prod\/imported-s3-bucket.tf` brings `aws_s3_bucket.acme_logs`/);
  assert.equal(opened[0].base, 'main');
  assert.equal(opened[0].branch, 'teriac/adopt/envs_prod-aws_s3_bucket-acme_logs');
  assert.equal(opened[0].title, 'Bring aws_s3_bucket.acme_logs under Terraform in envs/prod');
  assert.deepEqual(opened[0].files.map((f: any) => f.path), ['envs/prod/imported-s3-bucket.tf']);
  assert.match(opened[0].body, /asked by carol in #12/);

  const again = await req(null);
  assert.match(again.message, /already open/);
  const missing = await app.adoptResources({ adapter, repo, policy, base: 'main', select: { project: 'envs/nope' }, targets: targets('aws_s3_bucket', 'x'), user: null });
  assert.match(missing.message, /No project `envs\/nope` on `main`/);

  // Dashboard jobs run in the background and record the outcome.
  const job = app.startAdopt({ adapter, repo, policy, base: 'main', project: 'envs/prod', targets: targets('aws_s3_bucket', 'acme-logs'), by: 'admin' });
  assert.equal(job.status, 'running');
  while (job.status === 'running') await new Promise(res => setTimeout(res, 20));
  assert.equal(job.status, 'failed'); // the fake adapter opens only one PR
  assert.match(job.message!, /already open/);

  // The App without Contents: write: said plainly, after the clean plan.
  const real = adapter.openPullRequest;
  adapter.openPullRequest = async () => { throw new Error('the GitHub App needs Contents: Read & write to open pull requests'); };
  const denied2 = await app.adoptResources({ adapter, repo, policy, base: 'main', select: { project: 'envs/prod' }, targets: targets('aws_s3_bucket', 'acme-logs'), user: null });
  assert.match(denied2.message, /plans cleanly, but the PR could not be opened: the GitHub App needs Contents: Read & write/);
  adapter.openPullRequest = real;

  const audit = store.auditLog(20);
  assert.ok(audit.some(a => a.action === 'adopt' && a.user === 'carol' && /opened https/.test(a.reason)));
  assert.ok(audit.some(a => a.action === 'adopt' && a.user === 'bob' && !a.allowed));
  store.close();
});

test('with AI: a failed AI request falls back to Terraform\'s own code, and says so', async () => {
  const call: AiCall = async () => { throw Object.assign(new Error('Access to Bedrock models is not allowed for this account'), { status: 400 }); };
  const ai = new Ai({ provider: 'bedrock', model: 'claude-opus-5-5', effort: 'medium', features: ['import'], timeoutMs: 1000 }, { call });
  const r = await run(repoDir(), targets('aws_s3_bucket', 'acme-logs'), {}, { ai, settings: { features: ['import'], model: 'claude-opus-5-5', effort: 'medium', review: 'push' } });
  assert.ok(r.ok, r.error ?? '');
  assert.equal(r.aiFailed, true);
  assert.equal(r.model, undefined);
  assert.equal(r.rounds, 1);
  assert.match(r.file!.content, /resource "aws_s3_bucket" "acme_logs"/);
  assert.match(adoptBody('envs/prod', 'main', r, { user: 'bob' }), /The AI request failed, so this is what Terraform generated/);
  assert.ok(ai.lastError, 'the failure shows on the dashboard');
});
