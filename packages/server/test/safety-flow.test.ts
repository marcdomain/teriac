// The safety features end to end through the App: real git checkouts, real SQLite,
// real rendering and RBAC; a fake `terraform` replays real plan output, and a fake
// GitHub answers reviews, compare views and check runs.
import { test, before, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, copyFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { App } from '../src/app.ts';
import { Store } from '../src/store.ts';
import { parseReposYaml, type ServerConfig } from '../src/config.ts';
import type { ToolResolver } from '../src/runner.ts';
import type { CheckRun, Comparison, Permission, PullRequestState, Repo, Review, VcsAdapter, VcsEvent } from '../src/vcs/types.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
let tmp: string;
let fixtures: string;
let origin: string;
let head: string;
let fakeTf: string;

const sh = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, encoding: 'utf-8' }).trim();

// Fake terraform. Markers in the project folder change what it prints:
//   LEAK      the plan output contains an AWS access key
//   SECURITY  the plan JSON has AWS resources the built-in security rules flag
const FAKE_TF = (F: string) => `#!/usr/bin/env node
const fs = require('fs'); const path = require('path');
const F = ${JSON.stringify(F)};
const [cmd, ...rest] = process.argv.slice(2);
if (cmd === 'init') { console.log('Terraform has been successfully initialized!'); process.exit(0); }
const plan = () => {
  fs.writeFileSync('GIT_ENV', JSON.stringify(Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith('GIT_CONFIG')))));
  const out = rest.find(a => a.startsWith('-out=')).slice(5);
  fs.writeFileSync(out, fs.existsSync('SECURITY') ? 'security' : 'changes');
  process.stdout.write(fs.readFileSync(path.join(F, 'plan-changes.txt')));
  if (fs.existsSync('LEAK')) { process.stdout.write('  + tags = { owner_key = "AKIAIOSF'); process.stdout.write('ODNN7EXAMPLE" }\\n'); }
  if (fs.existsSync('SENSITIVE')) console.log('      - output = { password = "hunter2-SUPERSECRET" }');
  process.exit(2);
};
if (cmd === 'plan') {
  // SLOW: a long plan, for cancel; SIGINT stops it, as it does Terraform.
  if (fs.existsSync('SLOW')) {
    process.on('SIGINT', () => { console.log('Interrupt received. Gracefully shutting down...'); process.exit(1); });
    setTimeout(plan, 8000);
  } else plan();
}
if (cmd === 'show' && rest[rest.length - 1] === '-json') {
  // The state: with a sensitive value when the project has a SENSITIVE marker.
  process.stdout.write(fs.existsSync('SENSITIVE') ? fs.readFileSync(path.join(F, 'state-sensitive.json')) : '{}');
  process.exit(0);
}
if (cmd === 'show') {
  const plan = fs.readFileSync(rest[rest.length - 1], 'utf-8');
  process.stdout.write(fs.readFileSync(path.join(F, plan === 'security' ? 'plan-security.json' : 'plan-changes.json')));
  process.exit(0);
}
if (cmd === 'apply' && fs.existsSync(path.join(path.dirname(process.argv[1]), 'apply-fail'))) { console.error('Error: creating bucket: AccessDenied'); process.exit(1); }
if (cmd === 'apply') { console.log('Apply complete! Resources: 3 added, 1 changed, 2 destroyed.'); process.exit(0); }
if (cmd === 'state' && rest[0] === 'list') { console.log('terraform_data.app'); process.exit(0); }
if (cmd !== 'plan') process.exit(1);
`;

const PERMS: Record<string, Permission> = { bob: 'write', carol: 'write', erin: 'maintain', alice: 'admin', mallory: 'none' };
const TEAMS: Record<string, string[]> = { 'platform-admins': ['alice', 'carol'], sre: ['erin'] };

class FakeGitHub implements VcsAdapter {
  readonly platform = 'github' as const;
  readonly commentLimit = 65000;
  readonly supportsChecks = true;
  comments: { id: string; pr: number; body: string }[] = [];
  private seq = 0;
  sticky = new Map<number, string>();
  checks = new Map<string, CheckRun>();
  reviewsByPr = new Map<number, Review[]>();
  prs = new Map<number, PullRequestState>();
  files = new Map<number, string[]>();
  // compare(base, head): the PR's own changes at `head` (base = main), or base-branch
  // changes since the PR left it (head = main).
  prFiles = new Map<string, Comparison>();
  baseChanges: Comparison | null = null;
  moduleAuth?: (r: Repo) => Promise<{ url: string; extraHeader?: string } | null>;
  merges: { method: string; sha: string }[] = [];
  mergeResult = { ok: true, message: 'Pull Request successfully merged' };
  deleted: string[] = [];
  async mergePullRequest(_r: Repo, _n: number, method: string, sha: string) { this.merges.push({ method, sha }); return this.mergeResult; }
  async deleteBranch(_r: Repo, branch: string) { this.deleted.push(branch); return true; }

  verify() { return true; }
  parse(): VcsEvent { return { kind: 'ignored', reason: 'test' }; }
  async getPullRequest(_r: Repo, n: number) { return this.prs.get(n)!; }
  async changedFiles(_r: Repo, n: number) { return this.files.get(n) ?? []; }
  async cloneAuth() { return { url: origin }; }
  async upsertComment(_r: Repo, n: number, _m: string, body: string) { this.sticky.set(n, body); return { id: `s${n}`, url: `https://github.test/pr/${n}#summary` }; }
  async comment(_r: Repo, n: number, body: string) { const id = String(++this.seq); this.comments.push({ id, pr: n, body }); return id; }
  async editComment(_r: Repo, id: string, body: string) { const c = this.comments.find(x => x.id === id); if (c) c.body = body; }
  async react() {}
  checkHistory: CheckRun[] = [];
  async setCheck(_r: Repo, c: CheckRun) { this.checks.set(c.name, c); this.checkHistory.push(c); return `https://github.test/runs/${encodeURIComponent(c.name)}`; }
  async userPermission(_r: Repo, u: string) { return PERMS[u] ?? 'none'; }
  async inTeam(_r: Repo, t: string, u: string) { return (TEAMS[t] ?? []).includes(u); }
  async reviews(_r: Repo, n: number) { return this.reviewsByPr.get(n) ?? []; }
  async fileAt() { return null; }
  async codeowners() { return null; }
  async listRepos() { return []; }
  async compare(_r: Repo, base: string, headRef: string) {
    if (headRef === 'main') return this.baseChanges;
    return this.prFiles.get(headRef) ?? null;
  }
  lastReply() { return this.comments[this.comments.length - 1]?.body ?? ''; }
}

const repo: Repo = { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '' };
const pr = (number: number, author: string): PullRequestState => ({
  number, title: 't', url: '', author, headSha: head, headRef: 'feat', baseRef: 'main',
  draft: false, fromFork: false, open: true, mergeable: true, behindBase: false,
});
const prChanges = (blob: string): Comparison => ({ files: [{ path: 'envs/dev/main.tf', status: 'modified', blob }, { path: 'envs/prod/main.tf', status: 'modified', blob }], commits: [], truncated: false });

// A fresh App, store and fake GitHub with these repos.yaml rules and server settings.
const RULES = `
    projects:
      - match: envs/prod
        permissions: { apply: [team:platform-admins], apply_destroy: [team:platform-admins] }
        approvals: [{ from: team:platform-admins, count: 1 }]
      - match: "**"
        approvals: [{ from: write, count: 1 }]`;
const setup = (repoExtra = '', server: Partial<ServerConfig> = {}) => {
  const dataDir = mkdtempSync(join(tmp, 'data-'));
  const store = new Store(':memory:');
  const gh = new FakeGitHub();
  const resolver: ToolResolver = { resolve: async () => ({ tool: { provider: 'terraform', version: '1.9.8', binary: fakeTf } }) };
  const config: ServerConfig = {
    port: 0, dataDir, publicUrl: 'https://teriac.example.com', parallelism: 2, runTimeoutMs: 60_000,
    commandNames: ['teriac'], defaultVersion: 'latest', requireApplyProject: false, ackReaction: 'none', progressReply: false, commentMode: 'update', spinnerUrl: null,
    auth: { sessionSecret: 'x'.repeat(32), sessionHours: 1, secureCookies: false, users: [] }, channels: {}, people: [],
    repos: parseReposYaml(`repos:\n  - id: github.com/acme/*\n${repoExtra}${RULES}\n`),
    ...server,
  };
  const app = new App({ config, store, resolver, env: { ...process.env } });
  gh.prs.set(1, pr(1, 'bob'));
  gh.files.set(1, ['envs/dev/main.tf', 'envs/prod/main.tf']);
  const say = (author: string, body: string) => app.handle(gh, { kind: 'comment', repo, prNumber: 1, commentId: '1', author, body });
  const open = () => app.handle(gh, { kind: 'pr_opened', repo, pr: pr(1, 'bob') });
  return { app, store, gh, say, open, dataDir };
};
const applies = (store: Store) => store.latestRuns('github.com/acme/infra', 1, 'apply');

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'teriac-safety-'));
  fixtures = join(tmp, 'fixtures');
  mkdirSync(fixtures);
  for (const f of ['plan-changes.txt', 'plan-changes.json', 'state-sensitive.json']) copyFileSync(join(FIXTURES, f), join(fixtures, f));
  writeFileSync(join(fixtures, 'plan-security.json'), JSON.stringify({
    format_version: '1.2',
    resource_changes: [
      { address: 'aws_s3_bucket_acl.logs', mode: 'managed', type: 'aws_s3_bucket_acl', name: 'logs', change: { actions: ['create'], before: null, after: { acl: 'public-read' }, after_unknown: {} } },
      { address: 'aws_security_group.ssh', mode: 'managed', type: 'aws_security_group', name: 'ssh', change: { actions: ['create'], before: null, after: { ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }] }, after_unknown: {} } },
    ],
  }));
  origin = join(tmp, 'origin');
  mkdirSync(join(origin, 'envs/dev'), { recursive: true });
  mkdirSync(join(origin, 'envs/prod'), { recursive: true });
  const tf = 'resource "terraform_data" "app_config" {}\n\nresource "terraform_data" "database" {\n  input = "db"\n}\n\nresource "terraform_data" "legacy_queue" {}\n';
  writeFileSync(join(origin, 'envs/dev/main.tf'), tf);
  writeFileSync(join(origin, 'envs/prod/main.tf'), tf);
  sh(origin, 'init', '-q', '-b', 'main');
  sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '.');
  sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'init');
  sh(origin, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  head = sh(origin, 'rev-parse', 'HEAD');
  fakeTf = join(tmp, 'terraform');
  writeFileSync(fakeTf, FAKE_TF(fixtures));
  chmodSync(fakeTf, 0o755);
});

after(() => rmSync(tmp, { recursive: true, force: true }));

// ---------------------------------------------------------------------------
describe('approvals and rebases', () => {
  test('default: an approval of an earlier commit does not count', async () => {
    const { gh, store, say, open } = setup();
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: 'before-rebase' }]);
    gh.prFiles.set(head, prChanges('b1'));
    gh.prFiles.set('before-rebase', prChanges('b1'));
    await say('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /envs\/dev`: 1 more approval from write/);
    assert.equal(applies(store).length, 0);
  });

  test('keep_approval_on_rebase: a rebase keeps it, and the comment says so', async () => {
    const { gh, store, say, open } = setup('    keep_approval_on_rebase: true\n');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: 'before-rebase' }]);
    gh.prFiles.set(head, prChanges('b1'));
    gh.prFiles.set('before-rebase', prChanges('b1'));
    await open();
    assert.match(gh.sticky.get(1)!, /\*\*Approved by\*\* .*carol.*<sub>\(carol: kept after a rebase that didn't change the PR's code\)<\/sub>/);
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
  });

  test('keep_approval_on_rebase: an edit after the approval needs a new one', async () => {
    const { gh, store, say, open } = setup('    keep_approval_on_rebase: true\n');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: 'before-edit' }]);
    gh.prFiles.set(head, prChanges('b2'));
    gh.prFiles.set('before-edit', prChanges('b1'));
    await open();
    await say('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /1 more approval from write/);
    assert.equal(applies(store).length, 0);
  });

  test('reapprove_on_change: false lets an earlier approval count', async () => {
    const { gh, store, say, open } = setup('    reapprove_on_change: false\n');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: 'long-ago' }]);
    await open();
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
  });
});

describe('out-of-date branches', () => {
  const base: Comparison = {
    files: [{ path: 'envs/dev/main.tf', status: 'modified', blob: 'x' }],
    commits: [{ sha: 'aaaaaaa1', message: 'bump instance size', author: 'ada', pr: 52 }],
    truncated: false,
  };
  test('warn (default): the comment warns on the affected project only; apply goes ahead with a heads-up', async () => {
    const { gh, store, say, open } = setup();
    gh.baseChanges = base;
    await open();
    const body = gh.sticky.get(1)!;
    const dev = body.slice(body.indexOf('<b>envs/dev</b>'), body.indexOf('<b>envs/prod</b>'));
    const prod = body.slice(body.indexOf('<b>envs/prod</b>'));
    assert.match(dev, /\[!WARNING\]\n> `main` has 1 newer commit that change files `envs\/dev` uses \(#52 by ada: bump instance size\)/);
    assert.doesNotMatch(prod, /newer commit/);
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
    assert.ok(gh.comments.some(c => /⚠️ `main` has 1 newer commit/.test(c.body)));
  });
  test('block: apply is refused until the branch is updated', async () => {
    const { gh, store, say, open } = setup('    stale_base: block\n');
    gh.baseChanges = base;
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /Not applied:.*\n- `envs\/dev`: `main` has 1 newer commit.*rebase or merge `main` first/s);
    assert.equal(applies(store).length, 0);
  });
  test('off: no compare calls, no warning', async () => {
    const { gh, open } = setup('    stale_base: off\n');
    let calls = 0;
    gh.compare = async () => { calls++; return base; };
    await open();
    assert.doesNotMatch(gh.sticky.get(1)!, /newer commit/);
    assert.equal(calls, 0);
  });
});

describe('apply exactly what was reviewed', () => {
  const planFile = (dataDir: string) => join(dataDir, 'plans', 'github.com', 'acme', 'infra', '1', 'envs_dev-default.tfplan');
  test('a plan file changed after review is refused and audited', async () => {
    const { gh, store, say, open, dataDir } = setup();
    await open();
    writeFileSync(planFile(dataDir), 'swapped');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    const run = applies(store).find(r => r.project === 'envs/dev')!;
    assert.equal(run.status, 'failed');
    assert.match(run.output, /refused to apply: the saved plan file changed since it was reviewed/);
    assert.ok(store.auditLog(20).some(a => a.action === 'apply' && !a.allowed && /plan file changed/.test(a.reason)));
  });
  test('verify_plan: false skips the check', async () => {
    const { gh, store, say, open, dataDir } = setup('    verify_plan: false\n');
    await open();
    writeFileSync(planFile(dataDir), 'swapped');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
  });
});

describe('leaked-secret scan', () => {
  const leak = (on: boolean) => {
    // The marker lives in the PR's checkout, made from origin; add and remove it there.
    const f = join(origin, 'envs/dev/LEAK');
    if (on) writeFileSync(f, ''); else rmSync(f, { force: true });
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', on ? 'leak' : 'no leak');
    head = sh(origin, 'rev-parse', 'HEAD');
  };
  test('redact (default): hidden in the comment, noted, audited', async () => {
    leak(true);
    try {
      const { gh, store, open } = setup();
      await open();
      const body = gh.sticky.get(1)!;
      assert.doesNotMatch(body, /AKIAIOSFODNN7EXAMPLE/);
      assert.match(body, /‹redacted: aws-access-key›/);
      assert.match(body, /\[!CAUTION\]\n> 🔐 Something that looks like a secret was hidden from this output \(aws-access-key\)/);
      const run = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!;
      assert.deepEqual([run.status, run.secrets], ['success', ['aws-access-key']]);
      assert.ok(store.auditLog(20).some(a => a.action === 'secret_found' && /aws-access-key/.test(a.reason)));
    } finally { leak(false); }
  });
  test('fail: the plan is withheld and cannot be applied', async () => {
    leak(true);
    try {
      const { gh, store, say, open } = setup('    secret_scan: fail\n');
      await open();
      const run = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!;
      assert.equal(run.status, 'failed');
      assert.equal(run.planPath, null);
      assert.match(run.output, /withheld this plan's output.*aws-access-key/);
      assert.doesNotMatch(gh.sticky.get(1)!, /AKIA/);
      gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
      await say('erin', 'teriac apply -p envs/dev');
      assert.equal(applies(store).length, 0);
    } finally { leak(false); }
  });
});

describe('change freezes and protected resources', () => {
  const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);
  const freezes = [{ name: 'release', projects: ['envs/prod'], from: day(-1), to: day(1), override: ['user:alice'] }];
  const approveProd = (gh: FakeGitHub) => gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'erin', state: 'approved', commitSha: head }]);

  test("a freeze blocks applies (plans still run); --override needs that window's override list", async () => {
    const { gh, store, say, open } = setup('', { freezes });
    await open();
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 2, 'plans still run');
    assert.match(gh.sticky.get(1)!, /\[`envs\/prod`\][^\n]*.*change freeze `release` is on until end of/);
    approveProd(gh);
    await say('alice', 'teriac apply -p envs/prod');
    assert.match(gh.lastReply(), /change freeze `release` is on/);
    await say('carol', 'teriac apply -p envs/prod --override');
    assert.match(gh.lastReply(), /change freeze `release` is on until [^·]* · \[alice\]\(https:\/\/github\.com\/alice\) can apply with `--override`/, 'carol is not in the list: still blocked, and told who can');
    await say('alice', 'teriac apply -p envs/prod --override');
    assert.equal(applies(store).find(r => r.project === 'envs/prod')?.status, 'success');
    assert.ok(store.auditLog(30).some(a => a.action === 'override' && a.allowed && /--override skipped: change freeze release/.test(a.reason)));
    assert.ok(store.auditLog(30).some(a => a.action === 'override' && !a.allowed && a.user === 'carol'));
  });

  test('a freeze also stops direct state edits', async () => {
    const { gh, say, open } = setup('', { freezes });
    await open();
    approveProd(gh);
    await say('alice', 'teriac state rm -p envs/prod terraform_data.app');
    assert.match(gh.lastReply(), /needs .*change freeze `release` is on/);
  });

  test('protected resources block apply, and are marked on the code', async () => {
    const prot = [{ resources: ['terraform_data.database'], override: ['team:sre'] }];
    const { gh, store, say, open } = setup('', { protected: prot });
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /protected resource would be destroyed or replaced: `terraform_data\.database` · team \[sre\]\([^)]+\) can apply with `--override`/);
    assert.equal(applies(store).length, 0);
    const notes = gh.checks.get('teriac: envs/dev')!.annotations!;
    const db = notes.find(n => n.title.startsWith('terraform_data.database'))!;
    assert.deepEqual([db.path, db.startLine, db.level], ['envs/dev/main.tf', 3, 'failure']);
    assert.match(db.title, /will be replaced \(protected\)/);
    const queue = notes.find(n => n.title.startsWith('terraform_data.legacy_queue'))!;
    assert.deepEqual([queue.startLine, queue.level, queue.title], [7, 'warning', 'terraform_data.legacy_queue will be destroyed']);
    // erin (team:sre) may override, with an approval.
    await say('erin', 'teriac apply -p envs/dev --override');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
  });
});

describe('risk', () => {
  test('the score shows in the table and section; high risk can need an extra approval', async () => {
    const risk = { extra_approval: { high: { from: 'team:sre', count: 1 } } };
    const { gh, store, say, open } = setup('', { risk });
    await open();
    const body = gh.sticky.get(1)!;
    assert.match(body, /\| Plan \| Risk \| Apply \|/);
    assert.match(body, /\*\*Risk: 🟠 High\*\* · destroys or replaces 2 resources in production\n/);
    assert.match(body, /\[`envs\/prod`\][^\n]*1 more approval from team:platform-admins; 1 more approval from team:sre \(high risk\)/);
    assert.doesNotMatch(body.slice(body.indexOf('| [`envs/dev`'), body.indexOf('| [`envs/prod`')), /\[`envs\/dev`\][^\n]*.*team:sre/, 'medium-risk dev needs no extra approval');
    assert.match(gh.checks.get('teriac: envs/prod')!.summary, /\*\*Risk: 🟠 High\*\*/);
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('alice', 'teriac apply -p envs/prod');
    assert.match(gh.lastReply(), /1 more approval from team:sre \(high risk\)/);
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'erin', state: 'approved', commitSha: head }]);
    await say('alice', 'teriac apply -p envs/prod');
    assert.equal(applies(store).find(r => r.project === 'envs/prod')?.status, 'success');
  });
});

describe('built-in security rules', () => {
  test('flagged on the plan, in the comment and on the code', async () => {
    writeFileSync(join(origin, 'envs/dev/SECURITY'), '');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'security');
    head = sh(origin, 'rev-parse', 'HEAD');
    try {
      const s2 = setup('', { policies: { mode: 'enforce', builtin: ['security'] } });
      await s2.open();
      const body = s2.gh.sticky.get(1)!;
      assert.match(body, /🛡️ \*\*Policy \(enforced: blocks apply\)/);
      assert.match(body, /\*\*aws-s3-public-acl\*\* · `aws_s3_bucket_acl\.logs` · bucket ACL "public-read"/);
      assert.match(body, /\*\*aws-security-group-open-ingress\*\* · `aws_security_group\.ssh` · open to the internet on port 22/);
      assert.match(body, /\[`envs\/dev`\][^\n]*.*2 policy findings \(aws-s3-public-acl, aws-security-group-open-ingress\)/);
    } finally {
      rmSync(join(origin, 'envs/dev/SECURITY'));
      sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
      sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'no security');
      head = sh(origin, 'rev-parse', 'HEAD');
    }
  });
});

describe('emergency access', () => {
  test('a grant gives the permission for its time; it is audited and its first use recorded', async () => {
    const { gh, store, say, open } = setup();
    await open();
    await say('mallory', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /apply on `envs\/dev` needs write/);
    const g = store.createGrant({ user: 'mallory', repo: 'github.com/acme/*', projects: ['envs/dev'], actions: ['apply', 'apply_destroy'], bypass: [], reason: 'INC-7 hotfix', grantedBy: 'Ada (oidc)', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    await say('mallory', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /1 more approval from write/, 'the grant covers the permission, not the approvals');
    const g2 = store.createGrant({ user: 'mallory', repo: '*', projects: [], actions: ['apply', 'apply_destroy'], bypass: ['approvals'], reason: 'INC-7 hotfix, no reviewer awake', grantedBy: 'Ada (oidc)', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    store.revokeGrant(g.id, 'Ada');
    await say('mallory', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success', gh.lastReply());
    assert.ok(store.auditLog(40).some(a => a.user === 'mallory' && a.allowed && new RegExp(`emergency access #${g2.id} from Ada`).test(a.reason)));
    assert.ok(store.getGrant(g2.id)!.usedAt);
    // Not for other projects' protections: an expired grant does nothing.
    (store as any).db.prepare('UPDATE grants SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), g2.id);
    await say('mallory', 'teriac apply -p envs/prod');
    assert.match(gh.lastReply(), /apply on `envs\/prod` needs team:platform-admins/);
  });
});

test('nothing here leaks the plan file path or server env into the comment', () => {
  // Guard against accidental debug output in the new paths.
  const src = readFileSync(join(import.meta.dirname, '..', 'src', 'app.ts'), 'utf-8');
  assert.doesNotMatch(src, /console\.log/);
});

// ---------------------------------------------------------------------------
describe('remaining paths', () => {
  const day = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10);
  const grant = (store: Store, bypass: string[], user = 'erin') => store.createGrant({
    user, repo: '*', projects: [], actions: ['apply', 'apply_destroy'], bypass, reason: 'incident', grantedBy: 'Ada', expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  });

  test('a grant can skip a freeze, a protected resource or an enforced policy (and only what it lists)', async () => {
    const freezes = [{ name: 'release', from: day(-1), to: day(1) }];
    const prot = [{ resources: ['terraform_data.database'] }];
    const rule = { name: 'no-db-replace', resource: 'terraform_data', actions: ['replace'] };
    const { gh, store, say, open } = setup('', { freezes, protected: prot, policies: { mode: 'enforce', rules: [rule] } });
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    const all = gh.lastReply();
    assert.match(all, /change freeze `release`/);
    assert.match(all, /protected resource/);
    assert.match(all, /1 policy finding \(no-db-replace\)/);
    const g = grant(store, ['freeze', 'protected']);
    await say('erin', 'teriac apply -p envs/dev');
    assert.doesNotMatch(gh.lastReply(), /change freeze|protected resource/);
    assert.match(gh.lastReply(), /1 policy finding/, 'policy is not in this grant');
    store.revokeGrant(g.id, 'Ada');
    grant(store, ['freeze', 'protected', 'policy']);
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(applies(store).find(r => r.project === 'envs/dev')?.status, 'success');
  });

  test('the first use of a grant is announced once', async () => {
    const sent: { event: string }[] = [];
    const real = globalThis.fetch;
    globalThis.fetch = (async (_u: string, init: RequestInit) => { sent.push(JSON.parse(String(init.body))); return new Response('ok'); }) as typeof fetch;
    process.env.TERIAC_TEST_HOOK = 'https://hook.test';
    try {
      const { store, say, open } = setup('', {
        breakGlass: { grantors: ['admin'], notify: ['ops'] }, channels: { ops: { type: 'webhook', webhook_url_env: 'TERIAC_TEST_HOOK' } },
      });
      await open();
      grant(store, ['approvals'], 'mallory');
      await say('mallory', 'teriac apply -p envs/dev');
      await say('mallory', 'teriac plan -p envs/dev');
      await say('mallory', 'teriac apply -p envs/dev');
      await new Promise(r => setTimeout(r, 50));
      assert.equal(sent.filter(m => m.event === 'teriac.break_glass.used').length, 1);
    } finally {
      globalThis.fetch = real;
      delete process.env.TERIAC_TEST_HOOK;
    }
  });

  test('apply output and command output are scanned too', async () => {
    const tf = readFileSync(fakeTf, 'utf-8');
    writeFileSync(fakeTf, tf
      .replace("console.log('Apply complete!", "console.log('token ghp_' + 'a'.repeat(36)); console.log('Apply complete!")
      .replace("console.log('terraform_data.app');", "console.log('terraform_data.app'); console.log('-----BEGIN RSA PRIVATE KEY-----\\\\nMIIE\\\\n-----END RSA PRIVATE KEY-----');"));
    try {
      const { gh, store, say, open } = setup();
      await open();
      gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
      await say('erin', 'teriac apply -p envs/dev');
      const run = applies(store).find(r => r.project === 'envs/dev')!;
      assert.equal(run.status, 'success');
      assert.doesNotMatch(run.output, /ghp_a/);
      assert.deepEqual(run.secrets, ['github-token']);
      await say('erin', 'teriac state list -p envs/dev');
      const reply = gh.comments.slice(-1)[0].body;
      assert.doesNotMatch(reply, /BEGIN RSA PRIVATE KEY/);
      assert.ok(gh.comments.some(c => /🔐 Something that looks like a secret was hidden/.test(c.body)));
      assert.ok(store.auditLog(40).filter(a => a.action === 'secret_found').length >= 2);
    } finally { writeFileSync(fakeTf, tf); }
  });

  test('policy findings get notes on the code', async () => {
    const rule = { name: 'no-db-replace', resource: 'terraform_data', actions: ['replace'], severity: 'critical' as const, message: 'never replace the database' };
    const { gh, open } = setup('', { policies: { mode: 'audit', rules: [rule] } });
    await open();
    const note = gh.checks.get('teriac: envs/dev')!.annotations!.find(a => a.title === 'Policy: no-db-replace')!;
    assert.deepEqual([note.path, note.startLine, note.level, note.message], ['envs/dev/main.tf', 3, 'failure', 'never replace the database']);
  });

  test("a repo's freezes add to the server's; a repo can make the secret scan stricter, not looser", async () => {
    const serverFreeze = [{ name: 'server-wide', projects: ['envs/prod'], from: day(-1), to: day(1) }];
    const { gh, open } = setup(`    freezes: [{ name: repo-only, projects: [envs/dev], from: "${day(-1)}", to: "${day(1)}" }]\n    secret_scan: off\n`, { freezes: serverFreeze, secretScan: { mode: 'fail' } });
    await open();
    const body = gh.sticky.get(1)!;
    assert.match(body, /\[`envs\/dev`\][^\n]*.*change freeze `repo-only`/);
    assert.match(body, /\[`envs\/prod`\][^\n]*.*change freeze `server-wide`/);
    // secret_scan: off in the repo can't loosen the server's "fail": the dev plan (no secret here) still succeeds,
    // and the mode in force is checked directly.
    const app = setup('    secret_scan: off\n', { secretScan: { mode: 'fail' } }).app as any;
    const ctx = { policy: { secret_scan: 'off' }, rulesConfig: {} };
    assert.equal(app.safety(ctx).secretMode, 'fail');
  });
});

// ---------------------------------------------------------------------------
describe('git credentials for module downloads', () => {
  const gitEnv = (dataDir: string) => JSON.parse(readFileSync(join(dataDir, 'work/github.com/acme/infra/1/envs/dev/GIT_ENV'), 'utf-8'));
  const read = async () => ({ url: 'https://github.com/', extraHeader: 'Authorization: Basic cmVhZC1vbmx5' });

  test('plans get the read-only token as a git header for the host', async () => {
    const { gh, open, dataDir } = setup();
    gh.moduleAuth = read;
    await open();
    assert.deepEqual(gitEnv(dataDir), { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0: 'Authorization: Basic cmVhZC1vbmx5' });
    assert.doesNotMatch(gh.sticky.get(1) ?? gh.lastReply(), /cmVhZC1vbmx5/, 'never shown in the PR');
  });

  test('TERIAC_MODULE_AUTH=false: no credentials', async () => {
    const { gh, open, dataDir } = setup('', { moduleAuth: false });
    gh.moduleAuth = read;
    await open();
    assert.deepEqual(gitEnv(dataDir), {});
  });

  test('a failed token request still plans, without credentials', async () => {
    const { gh, open, dataDir, store } = setup();
    gh.moduleAuth = async () => { throw new Error('HTTP 502'); };
    await open();
    assert.deepEqual(gitEnv(dataDir), {});
    assert.ok(store.latestRuns('github.com/acme/infra', 1, 'plan').every(r => r.status === 'success'));
  });
});

describe('avatars in the comment', () => {
  test('round, from the server, when GitHub can reach it; else GitHub\'s square photo', async () => {
    const pub = setup('', { spinnerUrl: 'https://teriac.example.com/assets/spinner.gif' });
    await pub.open();
    const body = [...pub.gh.sticky.values(), ...pub.gh.comments.map(c => c.body)].join('\n');
    assert.match(body, /<img src="https:\/\/teriac\.example\.com\/avatars\/round\/github\.com\/bob\.svg" width="18" height="18"/);
    const priv = setup();
    await priv.open();
    const body2 = [...priv.gh.sticky.values(), ...priv.gh.comments.map(c => c.body)].join('\n');
    assert.match(body2, /<img src="https:\/\/github\.com\/bob\.png\?size=36"/);
    assert.doesNotMatch(body2, /avatars\/round/);
  });
});

// ---------------------------------------------------------------------------
describe('live output, secrets and cleanup', () => {
  // Markers committed to the repo change what the fake terraform prints in envs/dev.
  const markers = (files: string[], on: boolean) => {
    for (const f of files) { const p = join(origin, 'envs/dev', f); if (on) writeFileSync(p, ''); else rmSync(p, { force: true }); }
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', on ? 'markers' : 'no markers');
    head = sh(origin, 'rev-parse', 'HEAD');
  };
  const liveLines = (app: any, store: Store) => {
    const run = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!;
    return { run, lines: app.live.subscribe(run.id, () => {})?.backlog ?? null };
  };

  test('a plan streams its output live: whole lines, secrets hidden, state-sensitive values hidden', async () => {
    markers(['LEAK', 'SENSITIVE'], true);
    let got: ReturnType<typeof liveLines>;
    try {
      const { app, store, open } = setup();
      await open();
      got = liveLines(app, store);
    } finally {
      markers(['LEAK', 'SENSITIVE'], false);
    }
    const { run, lines } = got;
    assert.ok(lines && lines.length > 5);
    const text = lines!.join('\n');
    assert.match(text, /^\$ terraform plan /m, 'commands are shown');
    assert.match(text, /owner_key = "‹redacted: aws-access-key›"/, 'a key split across two chunks is caught');
    assert.match(text, /password = "\(sensitive value\)"/, 'a value the state marks sensitive');
    assert.doesNotMatch(text, /AKIAIOSF|hunter2/);
    assert.doesNotMatch(text, /show -json/, 'teriac\'s own reads are not shown');
    assert.doesNotMatch(run.output, /AKIAIOSF|hunter2/, 'nor in the saved output');
  });

  test('unlock deletes the saved plan files and live output; closing the PR drops the rest', async () => {
    const { app, store, say, open, gh } = setup();
    await open();
    const plans = store.latestRuns('github.com/acme/infra', 1, 'plan');
    const files = plans.map(r => r.planPath!).filter(Boolean);
    assert.equal(files.length, 2);
    assert.ok(files.every(f => existsSync(f) && existsSync(`${f}.json`)));
    const dev = plans.find(r => r.project === 'envs/dev')!;
    const prod = plans.find(r => r.project === 'envs/prod')!;
    await say('bob', 'teriac unlock -p envs/dev');
    assert.ok(!existsSync(dev.planPath!) && !existsSync(`${dev.planPath}.json`), 'that project\'s plan is gone');
    assert.equal(app.live.has(dev.id), false, 'and its live output');
    assert.ok(existsSync(prod.planPath!), 'the other project keeps its plan');
    assert.equal(store.getRun(dev.id)!.planPath, null);
    await app.handle(gh, { kind: 'pr_closed', repo, pr: pr(1, 'bob'), merged: true });
    assert.ok(!existsSync(prod.planPath!), 'closing deletes the rest');
    assert.equal(app.live.has(prod.id), false);
  });

  test('-var-file must stay inside the checkout, even through a symlink', async () => {
    const { varFileEscape } = await import('../src/app.ts');
    const { symlinkSync } = await import('node:fs');
    const root = mkdtempSync(join(tmp, 'vf-'));
    mkdirSync(join(root, 'envs/dev'), { recursive: true });
    writeFileSync(join(root, 'envs/dev/prod.tfvars'), 'a = 1');
    symlinkSync('/etc/hosts', join(root, 'envs/dev/evil.tfvars'));
    const project = { name: 'envs/dev', dir: 'envs/dev' } as any;
    assert.equal(varFileEscape(root, project, ['-var-file=prod.tfvars']), null);
    assert.match(varFileEscape(root, project, ['-var-file', 'evil.tfvars'])!, /points outside the repo/);
    assert.match(varFileEscape(root, project, ['-var-file=missing.tfvars'])!, /doesn't exist/);
  });
});

test('while a plan runs, its check links to the live output (the PR\'s "Details" link)', async () => {
  const { gh, open } = setup();
  await open();
  const running = gh.checkHistory.find(c => c.name === 'teriac: envs/dev' && c.status === 'in_progress')!;
  assert.match(running.detailsUrl!, /^https:\/\/teriac\.example\.com\/#runs\/acme\/infra\/pull\/1\/\d+$/);
  assert.match(running.summary, /▶ \[Watch the live output\]\(https:\/\/teriac\.example\.com\/#runs\/acme\/infra\/pull\/1\/\d+\)/);
});

// ---------------------------------------------------------------------------
describe('pull requests from forks', () => {
  const forkPr = () => ({ ...pr(1, 'bob'), fromFork: true });

  test('not planned on open or push: nothing is checked out, one comment says why', async () => {
    const { gh, store, app, dataDir } = setup();
    gh.prs.set(1, forkPr());
    await app.handle(gh, { kind: 'pr_opened', repo, pr: forkPr() });
    await app.handle(gh, { kind: 'pr_updated', repo, pr: forkPr() });
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 0);
    assert.ok(!existsSync(join(dataDir, 'work/github.com/acme/infra/1')), 'the fork\'s code was never checked out');
    assert.match(gh.sticky.get(1)!, /doesn't plan or apply pull requests from forks/);
  });

  test('commands on a fork PR are refused and audited, even from an admin', async () => {
    const { gh, store, say } = setup();
    gh.prs.set(1, forkPr());
    await say('alice', 'teriac plan -p envs/dev');
    assert.match(gh.lastReply(), /doesn't plan or apply pull requests from forks/);
    await say('alice', 'teriac apply -p envs/dev');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 0);
    assert.ok(store.auditLog(10).some(a => !a.allowed && a.reason === 'pull request from a fork'));
    await say('alice', 'teriac help');
    assert.doesNotMatch(gh.lastReply(), /forks/, 'help still works');
  });

  test('allow_fork_prs: true plans them (the author still needs plan rights)', async () => {
    const { gh, store, app } = setup('    allow_fork_prs: true\n');
    gh.prs.set(1, forkPr());
    await app.handle(gh, { kind: 'pr_opened', repo, pr: forkPr() });
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 2);
  });
});

test('after a successful apply its plan file is deleted; the runs, output and comments stay', async () => {
  const { gh, store, say, open } = setup();
  await open();
  gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
  const plan = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!;
  assert.ok(existsSync(plan.planPath!));
  const comments = gh.comments.length;
  await say('erin', 'teriac apply -p envs/dev');
  const apply = store.latestRuns('github.com/acme/infra', 1, 'apply').find(r => r.project === 'envs/dev')!;
  assert.equal(apply.status, 'success');
  assert.ok(!existsSync(plan.planPath!) && !existsSync(`${plan.planPath}.json`), 'plan file and its JSON deleted');
  const kept = store.getRun(plan.id)!;
  assert.ok(kept.output.length > 0 && kept.summary, 'the plan run keeps its output and summary');
  assert.ok(gh.comments.length > comments && gh.sticky.get(1), 'comments are added, never removed');
});

// ---------------------------------------------------------------------------
describe('project globs, pause all applies, apply notifications, cancel', () => {
  test('-p takes a glob', async () => {
    const { store, say, open } = setup();
    await open();
    const before = store.latestRuns('github.com/acme/infra', 1, 'plan').map(r => r.id);
    await say('bob', "teriac plan -p 'envs/*'");
    const after = store.latestRuns('github.com/acme/infra', 1, 'plan').filter(r => !before.includes(r.id)).map(r => r.project).sort();
    assert.deepEqual(after, ['envs/dev', 'envs/prod']);
  });

  test('a glob can\'t apply several projects where applies are one at a time', async () => {
    const { gh, say, open } = setup('', { requireApplyProject: true });
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    await say('alice', 'teriac apply -p envs/*');
    assert.match(gh.lastReply(), /applies one project at a time, and `envs\/\*` matches 2/);
  });

  test('pausing all applies blocks them everywhere until resumed', async () => {
    const { app, gh, store, say, open } = setup();
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
    app.pauseApplies({ by: 'ada', via: 'okta', at: '2026-11-15T10:00:00.000Z', reason: 'cloud provider incident' });
    await say('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /applies are paused from the teriac dashboard by ada since 2026-11-15 10:00 UTC \(cloud provider incident\)/);
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').length, 0);
    app.resumeApplies();
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').find(r => r.project === 'envs/dev')?.status, 'success');
  });

  test('notify_applies: one message per apply, with the counts and a link', async () => {
    const { createServer } = await import('node:http');
    const got: any[] = [];
    const hook = createServer((req, res) => { let b = ''; req.on('data', d => { b += d; }).on('end', () => { got.push(JSON.parse(b)); res.end('ok'); }); });
    await new Promise<void>(r => hook.listen(0, '127.0.0.1', () => r()));
    process.env.TEST_APPLY_HOOK = `http://127.0.0.1:${(hook.address() as any).port}/`;
    try {
      const { gh, say, open } = setup('    notify_applies: [ops]\n', { channels: { ops: { type: 'webhook', webhook_url_env: 'TEST_APPLY_HOOK' } } as any });
      await open();
      gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }]);
      await say('erin', 'teriac apply -p envs/dev');
      for (let i = 0; i < 40 && !got.length; i++) await new Promise(r => setTimeout(r, 50));
      assert.equal(got.length, 1);
      assert.equal(got[0].event, 'teriac.apply');
      assert.match(got[0].title, /Applied envs\/dev/);
      assert.match(JSON.stringify(got[0]), /#runs\/acme\/infra\/pull\/1\/\d+/);
    } finally {
      delete process.env.TEST_APPLY_HOOK;
      hook.close();
    }
  });

  test('cancel: drops queued plans and stops the running one (it skips the PR\'s queue)', async () => {
    const f = join(origin, 'envs/dev/SLOW'); const g = join(origin, 'envs/prod/SLOW');
    writeFileSync(f, ''); writeFileSync(g, '');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'slow');
    head = sh(origin, 'rev-parse', 'HEAD');
    try {
      const { app, gh, store, say, open } = setup('', { parallelism: 2, prParallelism: 1 });
      const planning = open();
      for (let i = 0; i < 100 && !store.latestRuns('github.com/acme/infra', 1, 'plan').some(r => r.status === 'running'); i++) await new Promise(r => setTimeout(r, 50));
      await new Promise(r => setTimeout(r, 500));
      const started = Date.now();
      await say('bob', 'teriac cancel');
      assert.match(gh.lastReply(), /Cancelled: 1 queued run dropped, 1 running plan stopped/);
      await planning;
      assert.ok(Date.now() - started < 6000, 'the slow plan was stopped, not waited for');
      const runs = store.latestRuns('github.com/acme/infra', 1, 'plan');
      assert.equal(runs.length, 1, 'the queued one never started');
      assert.equal(runs[0].status, 'failed');
      assert.match(runs[0].output, /cancelled/);
      assert.ok(store.auditLog(5).some(a => a.action === 'cancel'));
      await say('mallory', 'teriac cancel');
      assert.match(gh.lastReply(), /Only the PR's author or people who can write/);
    } finally {
      rmSync(f, { force: true }); rmSync(g, { force: true });
      sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'add', '-A');
      sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'not slow');
      head = sh(origin, 'rev-parse', 'HEAD');
    }
  });
});

// ---------------------------------------------------------------------------
describe('automerge', () => {
  test('merges once every planned change is applied, not before; deletes the branch if asked', async () => {
    const { gh, say, open } = setup('    automerge: { method: squash, delete_branch: true }\n');
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    await say('erin', 'teriac apply -p envs/dev');
    assert.equal(gh.merges.length, 0, 'envs/prod still has changes to apply');
    await say('alice', 'teriac apply -p envs/prod');
    assert.deepEqual(gh.merges, [{ method: 'squash', sha: head }], 'that exact commit, squashed');
    assert.deepEqual(gh.deleted, ['feat']);
    assert.match(gh.lastReply(), /teriac merged this PR \(squash\) and deleted `feat`/);
  });

  test('a refused merge says why; off by default', async () => {
    const on = setup('    automerge: true\n');
    await on.open();
    on.gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    on.gh.mergeResult = { ok: false, message: 'Required status check "ci" is expected' };
    await on.say('alice', 'teriac apply');
    assert.match(on.gh.lastReply(), /couldn't merge this PR: Required status check "ci" is expected/);
    const off = setup();
    await off.open();
    off.gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    await off.say('alice', 'teriac apply');
    assert.equal(off.gh.merges.length, 0);
  });
});

// ---------------------------------------------------------------------------
describe('hooks (server config only)', () => {
  test('run around plan and apply; post_plan sees the plan; a failing pre_apply stops the apply', async () => {
    const { gh, say, open, store } = setup([
      '    hooks:',
      '      pre_plan: [{ name: lint, run: "echo linted" }]',
      '      post_plan: [{ name: check, run: "test -f \\"$PLAN_FILE\\" && echo saw the plan" }]',
      '      pre_apply: [{ name: gate, run: "echo no deploys today; exit 3" }]',
      '',
    ].join('\n'));
    await open();
    const plan = store.latestRuns('github.com/acme/infra', 1, 'plan')[0];
    assert.match(plan.output, /\$ hook lint: echo linted\nlinted/);
    assert.match(plan.output, /saw the plan/);
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    await say('alice', 'teriac apply -p envs/dev');
    const apply = store.latestRuns('github.com/acme/infra', 1, 'apply')[0];
    assert.equal(apply.status, 'failed');
    assert.match(apply.output, /no deploys today\n\[teriac\] hook gate failed \(exit 3\)/);
    assert.doesNotMatch(apply.output, /Apply complete/);
  });

  test('bad hooks are refused at start-up', async () => {
    const { parseServerPolicy } = await import('../src/config.ts');
    assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    hooks: { pre_deploy: [] }\n'), /unknown stage "pre_deploy"/);
    assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    hooks: { pre_plan: [{ name: x }] }\n'), /needs a name and a run command/);
  });
});

// ---------------------------------------------------------------------------
describe('the end of a project in a PR: apply, unlock, merge, close', () => {
  const REPO = 'github.com/acme/infra';
  const approve = (gh: any) => gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
  const lockOf = (store: any, project: string) => store.getLock(REPO, project, 'default');
  const planFile = (store: any, project: string) => store.latestRuns(REPO, 1, 'plan').find((r: any) => r.project === project)?.planPath as string | null;
  const other = async (app: any, gh: any) => {
    gh.prs.set(2, pr(2, 'carol'));
    gh.files.set(2, ['envs/dev/main.tf']);
    await app.handle(gh, { kind: 'pr_opened', repo, pr: pr(2, 'carol') });
    return gh.sticky.get(2) as string;
  };

  test('default: an applied project stays locked to its PR (so no other PR undoes it) and says so', async () => {
    const { app, gh, say, open, store } = setup();
    await open();
    approve(gh);
    await say('alice', 'teriac apply -p envs/dev');
    assert.equal(lockOf(store, 'envs/dev')?.pr, 1);
    assert.equal(planFile(store, 'envs/dev'), null, 'the applied plan file is freed');
    assert.match(gh.comments.map((c: any) => c.body).join('\n'), /🔒 `envs\/dev` stays locked to this PR until it's merged or closed\. To free it sooner, comment `teriac unlock -p envs\/dev`\./);
    assert.match(await other(app, gh), /locked by #1 \(bob\)/);
    // Merging frees it, and the other PR can plan.
    await app.handle(gh, { kind: 'pr_closed', repo, pr: pr(1, 'bob'), merged: true });
    assert.equal(lockOf(store, 'envs/dev'), null);
  });

  test('unlock_after_apply: only applied projects are freed; a failed apply keeps its lock', async () => {
    const { app, gh, say, open, store } = setup('    unlock_after_apply: true\n');
    await open();
    approve(gh);
    await say('alice', 'teriac apply -p envs/dev');
    assert.equal(lockOf(store, 'envs/dev'), null, 'applied: free');
    assert.equal(lockOf(store, 'envs/prod')?.pr, 1, 'planned, not applied: still held');
    assert.doesNotMatch(gh.comments.map((c: any) => c.body).join('\n'), /stays locked/);
    assert.doesNotMatch(await other(app, gh), /locked by #1/);

    const failing = setup('    unlock_after_apply: true\n');
    await failing.open();
    approve(failing.gh);
    const flag = join(dirname(fakeTf), 'apply-fail');
    writeFileSync(flag, '');
    try { await failing.say('alice', 'teriac apply -p envs/dev'); } finally { rmSync(flag, { force: true }); }
    assert.equal(failing.store.latestRuns(REPO, 1, 'apply')[0]?.status, 'failed');
    assert.equal(lockOf(failing.store, 'envs/dev')?.pr, 1, 'failed apply: still held');
  });

  test('unlock -p discards the project\'s plan even when its lock is already free', async () => {
    const { gh, say, open, store } = setup();
    await open();
    const path = planFile(store, 'envs/dev')!;
    assert.ok(path && existsSync(path));
    store.releaseLock(REPO, 'envs/dev', 'default'); // e.g. freed from the dashboard earlier
    await say('bob', 'teriac unlock -p envs/dev');
    assert.equal(existsSync(path), false);
    assert.match(gh.lastReply(), /discarded the saved plans of `envs\/dev`/);
    assert.ok(planFile(store, 'envs/prod'), 'other projects keep theirs');
  });

  test('closing without merging frees every lock and deletes the plans', async () => {
    const { app, gh, open, store } = setup();
    await open();
    const paths = ['envs/dev', 'envs/prod'].map(p => planFile(store, p)!);
    await app.handle(gh, { kind: 'pr_closed', repo, pr: pr(1, 'bob'), merged: false });
    assert.equal(store.locksForPr(REPO, 1).length, 0);
    for (const p of paths) assert.equal(existsSync(p), false);
  });
});

describe('a plan is applied once', () => {
  test('after a failed apply the plan is deleted; applying again asks for a new plan', async () => {
    const { gh, say, open, store } = setup();
    await open();
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    const path = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!.planPath!;
    const flag = join(dirname(fakeTf), 'apply-fail');
    writeFileSync(flag, '');
    try { await say('alice', 'teriac apply -p envs/dev'); } finally { rmSync(flag, { force: true }); }
    assert.equal(existsSync(path), false, 'the plan file is gone');
    assert.match(gh.comments.map(c => c.body).join('\n'), /❌ The plan for `envs\/dev` was used up by the failed apply\. Fix the problem, then comment `teriac plan -p envs\/dev` and apply the new plan\./);
    const before = store.latestRuns('github.com/acme/infra', 1, 'apply').length;
    await say('alice', 'teriac apply -p envs/dev');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').filter(r => r.status === 'success').length, 0, 'nothing applied without a new plan');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').length, before);
    assert.match(gh.lastReply(), /`envs\/dev`: no plan at the current commit; run `teriac plan` first/);
    // A new plan, then the apply works.
    await say('alice', 'teriac plan -p envs/dev');
    await say('alice', 'teriac apply -p envs/dev');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').find(r => r.project === 'envs/dev')!.status, 'success');
  });
});

describe('commands from the API', () => {
  test('the same rules as a comment: permissions, approvals; the result goes on the PR', async () => {
    const { app, gh, open, store } = setup();
    await open();
    const api = (user: string, text: string) => app.handle(gh, { kind: 'api_command', repo, prNumber: 1, user, text, via: 'API token' });
    await api('erin', 'teriac apply -p envs/dev');
    assert.match(gh.lastReply(), /`teriac apply -p envs\/dev`, run for erin from the teriac API \(API token\)/);
    assert.match(gh.lastReply(), /1 more approval from write/, 'no approvals yet: refused like a comment');
    gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: head }, { user: 'alice', state: 'approved', commitSha: head }]);
    await api('erin', 'teriac apply -p envs/dev');
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'apply').find(r => r.project === 'envs/dev')?.status, 'success');
    assert.ok(store.searchAudit({ action: 'api_command' }).total >= 2);
  });
});

describe('depends_on in teriac.yaml (plain Terraform)', () => {
  // A commit whose teriac.yaml says envs/prod depends on envs/dev.
  const depsCommit = () => {
    sh(origin, 'checkout', '-q', '-B', 'deps', head);
    writeFileSync(join(origin, 'teriac.yaml'), 'projects:\n  - dir: envs/dev\n  - dir: envs/prod\n    depends_on: [envs/dev]\n');
    sh(origin, 'add', 'teriac.yaml');
    sh(origin, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'deps');
    const sha = sh(origin, 'rev-parse', 'HEAD');
    sh(origin, 'checkout', '-q', 'main');
    return sha;
  };
  const start = async (s: ReturnType<typeof setup>, sha: string) => {
    const p = { ...pr(1, 'bob'), headSha: sha };
    s.gh.prs.set(1, p);
    await s.app.handle(s.gh, { kind: 'pr_opened', repo, pr: p });
    s.gh.reviewsByPr.set(1, [{ user: 'carol', state: 'approved', commitSha: sha }, { user: 'alice', state: 'approved', commitSha: sha }]);
  };
  const REPO = 'github.com/acme/infra';

  test('dev applies first; prod is planned again with dev\'s new state, not applied', async () => {
    const sha = depsCommit();
    const s = setup();
    await start(s, sha);
    const prodPlan = s.store.latestRuns(REPO, 1, 'plan').find(r => r.project === 'envs/prod')!.id;
    await s.say('alice', 'teriac apply');
    const applies = s.store.latestRuns(REPO, 1, 'apply');
    assert.deepEqual(applies.map(a => [a.project, a.status]), [['envs/dev', 'success']], 'only dev was applied');
    assert.ok(s.store.latestRuns(REPO, 1, 'plan').find(r => r.project === 'envs/prod')!.id > prodPlan, 'prod has a new plan');
    assert.match(s.gh.comments.map(c => c.body).join('\n'), /re-planned after `envs\/dev` applied/);
  });

  test('if dev fails to apply, prod is skipped', async () => {
    const sha = depsCommit();
    const s = setup();
    await start(s, sha);
    const flag = join(dirname(fakeTf), 'apply-fail');
    writeFileSync(flag, '');
    try { await s.say('alice', 'teriac apply'); } finally { rmSync(flag, { force: true }); }
    assert.deepEqual(s.store.latestRuns(REPO, 1, 'apply').map(a => [a.project, a.status]), [['envs/dev', 'failed']]);
    assert.match(s.gh.comments.map(c => c.body).join('\n'), /`envs\/prod`: skipped: `envs\/dev` failed to apply first/);
  });
});

describe('the unlock permission (releasing another PR\'s lock from the dashboard)', () => {
  test('default maintain; a project can name who may unlock it', async () => {
    const { app, gh } = setup('', { repos: parseReposYaml(`repos:
  - id: github.com/acme/*
    projects:
      - match: envs/prod
        permissions: { unlock: [team:sre] }
`) });
    gh.prs.set(5, pr(5, 'bob'));
    const lock = (project: string) => ({ repo: 'github.com/acme/infra', project, workspace: 'default', pr: 5 });
    assert.equal((await app.mayUnlock(gh, lock('envs/dev'), 'erin')).allowed, true, 'maintain: the default');
    assert.equal((await app.mayUnlock(gh, lock('envs/dev'), 'bob')).allowed, false, 'write is not enough');
    assert.equal((await app.mayUnlock(gh, lock('envs/prod'), 'erin')).allowed, true, 'in team:sre');
    const alice = await app.mayUnlock(gh, lock('envs/prod'), 'alice');
    assert.equal(alice.allowed, false, 'a repo admin outside team:sre');
    assert.match(alice.reason, /team:sre/);
  });
});

describe('restarts', () => {
  test('while shutting down, new and queued events are saved, then replayed on the next start', async () => {
    const { app, gh, store } = setup();
    gh.prs.set(1, pr(1, 'bob'));
    app.drain();
    await app.handle(gh, { kind: 'comment', repo, prNumber: 1, commentId: '1', author: 'bob', body: 'teriac plan' });
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 0, 'not run while shutting down');
    // The next server: same database.
    const next = new App({ config: (app as any).deps.config, store, resolver: (app as any).deps.resolver, env: { ...process.env } });
    assert.equal(await next.replayPending(() => gh), 1);
    assert.equal(store.latestRuns('github.com/acme/infra', 1, 'plan').length, 2, 'planned after the restart');
    assert.equal(await next.replayPending(() => gh), 0, 'replayed once');
  });

  test('runs cut short by a crash: marked failed, checks finished, plan dropped, the PR told what to do', async () => {
    const { app, gh, store, open } = setup();
    await open();
    const plan = store.latestRuns('github.com/acme/infra', 1, 'plan').find(r => r.project === 'envs/dev')!;
    const stuckPlan = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'envs/dev', workspace: 'default', kind: 'plan', headSha: head, user: 'bob' });
    const stuckApply = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'envs/prod', workspace: 'default', kind: 'apply', headSha: head, user: 'alice' });
    assert.equal(await app.recoverInterrupted(() => gh), 2);
    assert.equal(store.getRun(stuckPlan)!.status, 'failed');
    assert.match(store.getRun(stuckApply)!.output, /the server restarted while this ran/);
    assert.equal(store.getRun(plan.id)!.planPath, null, "the project's saved plan is dropped");
    assert.equal(gh.checks.get('teriac: envs/prod')!.conclusion, 'cancelled');
    const msg = gh.lastReply();
    assert.match(msg, /teriac restarted while this PR had work running/);
    assert.match(msg, /Apply of `envs\/prod`: it may have stopped part-way\. Comment `teriac plan -p envs\/prod`.*force-unlock -p envs\/prod <lock-id>/);
    assert.equal(await app.recoverInterrupted(() => gh), 0, 'once');
  });
});
