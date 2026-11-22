import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import {
  Ai, loadAiConfig, clean, planDigest, raiseRisk, applyEdits, checkPolicyDraft, projectFiles,
  type AiCall, type AiConfig, type PlanReview,
} from '../src/ai.ts';
import { parseCommand, helpText } from '../src/commands.ts';
import { aiLines } from '../src/render.ts';
import { planDriftFix, aiDriftFix, driftFixBody } from '../src/driftfix.ts';
import type { Run } from '../src/store.ts';

const fixture = (f: string) => readFileSync(join(import.meta.dirname, 'fixtures', f), 'utf-8');
const cfg: AiConfig = { provider: 'anthropic', model: 'claude-opus-5-5', effort: 'medium', features: ['review', 'fix', 'drift', 'policy', 'ask'], timeoutMs: 1000 };

// A fake Claude that answers every request with `answer` and records what was sent.
const fake = (answer: unknown, stop = 'end_turn') => {
  const sent: any[] = [];
  const call: AiCall = async (params) => {
    sent.push(params);
    return { id: 'm', type: 'message', role: 'assistant', model: params.model, content: [{ type: 'text', text: JSON.stringify(answer) }], stop_reason: stop, stop_details: null, usage: { input_tokens: 1, output_tokens: 1 } } as any;
  };
  return { call, sent };
};

test('config: off by default; provider, effort and features are checked', () => {
  assert.equal(loadAiConfig({}), undefined);
  assert.equal(loadAiConfig({ TERIAC_AI_PROVIDER: 'off' }), undefined);
  const c = loadAiConfig({ TERIAC_AI_PROVIDER: 'anthropic' })!;
  assert.deepEqual([c.model, c.effort, c.features.length], ['claude-opus-5-5', 'medium', 5]);
  assert.equal(loadAiConfig({ TERIAC_AI_PROVIDER: 'bedrock', AWS_REGION: 'eu-west-1' })!.model, 'anthropic.claude-opus-5-5');
  assert.deepEqual(loadAiConfig({ TERIAC_AI_PROVIDER: 'anthropic', TERIAC_AI_FEATURES: 'review, ask' })!.features, ['review', 'ask']);
  assert.throws(() => loadAiConfig({ TERIAC_AI_PROVIDER: 'openai' }), /must be one of anthropic, bedrock, vertex, foundry/);
  assert.throws(() => loadAiConfig({ TERIAC_AI_PROVIDER: 'anthropic', TERIAC_AI_FEATURES: 'review,approve' }), /unknown feature "approve"/);
  assert.throws(() => loadAiConfig({ TERIAC_AI_PROVIDER: 'anthropic', TERIAC_AI_EFFORT: 'huge' }), /TERIAC_AI_EFFORT/);
  assert.throws(() => loadAiConfig({ TERIAC_AI_PROVIDER: 'bedrock' }), /AWS_REGION/);
  assert.throws(() => loadAiConfig({ TERIAC_AI_PROVIDER: 'vertex' }), /ANTHROPIC_VERTEX_PROJECT_ID/);
});

test('cleaning: sensitive values and secrets never reach the request', async () => {
  const plan = JSON.parse(fixture('plan-sensitive.json'));
  assert.ok(planDigest(plan).includes('hunter2-SUPERSECRET'), 'the raw digest has it');
  const { call, sent } = fake({ summary: 'Raises replicas to 3.', findings: [] });
  const ai = new Ai(cfg, { call });
  const r = await ai.reviewPlan({ project: 'db', production: false, engine: 'terraform 1.9.8', plan, risk: null, findings: [] });
  assert.equal(r?.summary, 'Raises replicas to 3.');
  const body = JSON.stringify(sent[0]);
  assert.ok(!body.includes('hunter2-SUPERSECRET'));
  assert.ok(body.includes('(sensitive value)'));
  assert.equal(clean('key AKIAABCDEFGHIJKLMNOP here'), 'key ‹redacted: aws-access-key› here');
});

test('review: findings are kept tidy, and risk only goes up', async () => {
  const plan = JSON.parse(fixture('plan-changes.json'));
  const { call, sent } = fake({ summary: 'x', findings: [
    { address: 'terraform_data.database', severity: 'critical', title: 'Data loss', why: 'replaced' },
    { address: 'terraform_data.cdn', severity: 'low', title: 'New CDN', why: 'fine' },
  ] });
  const r = (await new Ai(cfg, { call }).reviewPlan({ project: 'p', production: true, engine: 'tf', plan, risk: { level: 'medium', reasons: ['changes production'] }, findings: [] }))!;
  assert.equal(r.findings.length, 2);
  assert.match(JSON.stringify(sent[0]), /\(production\)/);
  assert.deepEqual(raiseRisk({ level: 'medium', reasons: ['a'] }, r), { level: 'critical', reasons: ['a', 'AI review: Data loss'] });
  const calm: PlanReview = { kind: 'review', model: 'm', summary: '', findings: [{ address: 'x', severity: 'low', title: 't', why: 'w' }] };
  assert.deepEqual(raiseRisk({ level: 'high', reasons: [] }, calm), { level: 'high', reasons: [] }, 'never lowers, low adds nothing');
  assert.equal(raiseRisk(null, r), null, 'no changes stays no risk');
});

test('a declined or failed request means no AI help, not an error', async () => {
  const declined = fake({}, 'refusal');
  assert.equal(await new Ai(cfg, { call: declined.call }).draftPolicy('anything'), null);
  const broken: AiCall = async () => { throw new Error('529 overloaded'); };
  assert.equal(await new Ai(cfg, { call: broken }).explainFailure({ project: 'p', kind: 'plan', output: 'x', root: '/nope', dir: '.' }), null);
});

test('failure help: only fixes inside the project files and their lines survive', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-ai-'));
  mkdirSync(join(tmp, 'envs/dev'), { recursive: true });
  writeFileSync(join(tmp, 'envs/dev/broken.tf'), 'resource "terraform_data" "x" { input = var.missing }\n');
  writeFileSync(join(tmp, 'envs/dev/.terraform.lock.hcl'), 'lock');
  writeFileSync(join(tmp, 'secret.tf'), 'outside the project');
  try {
    assert.deepEqual(projectFiles(tmp, 'envs/dev').map(f => f.path), ['envs/dev/broken.tf']);
    const { call, sent } = fake({ cause: 'var.missing is not declared.', fixes: [
      { path: 'envs/dev/broken.tf', start_line: 1, end_line: 1, replacement: 'variable "missing" {}\nresource "terraform_data" "x" { input = var.missing }\n', why: 'declare it' },
      { path: 'secret.tf', start_line: 1, end_line: 1, replacement: 'x', why: 'outside' },
      { path: 'envs/dev/broken.tf', start_line: 5, end_line: 9, replacement: 'x', why: 'past the end' },
    ] });
    const r = (await new Ai(cfg, { call }).explainFailure({ project: 'envs/dev', kind: 'plan', output: fixture('plan-error.txt'), root: tmp, dir: 'envs/dev' }))!;
    assert.equal(r.cause, 'var.missing is not declared.');
    assert.deepEqual(r.fixes.map(f => [f.path, f.startLine, f.endLine]), [['envs/dev/broken.tf', 1, 1]]);
    assert.equal(r.fixes[0].replacement, 'variable "missing" {}\nresource "terraform_data" "x" { input = var.missing }', 'trailing newlines dropped');
    assert.match(JSON.stringify(sent[0]), /1\| resource/, 'files are sent with line numbers');
    assert.ok(!JSON.stringify(sent[0]).includes('outside the project'));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test('line edits: bottom first, overlaps and unknown files skipped', () => {
  const files = new Map([['a.tf', '1\n2\n3\n4\n5']]);
  const r = applyEdits(files, [
    { path: 'a.tf', startLine: 2, endLine: 3, replacement: 'two\nthree\nmore' },
    { path: 'a.tf', startLine: 3, endLine: 4, replacement: 'overlap' },
    { path: 'a.tf', startLine: 5, endLine: 5, replacement: 'five' },
    { path: 'b.tf', startLine: 1, endLine: 1, replacement: 'x' },
  ]);
  assert.equal(files.get('a.tf'), '1\ntwo\nthree\nmore\n4\nfive');
  assert.equal(r.applied.length, 2);
  assert.equal(r.skipped.length, 2);
});

test('policy drafts: rules are built and checked against their own tests', () => {
  const d = checkPolicyDraft({
    rules: [
      { name: 'no-public-buckets', description: 'Buckets stay private', severity: 'high', resource: 'aws_s3_bucket_public_access_block', projects: ['prod/**'], actions: [], kind: 'require', condition: { attribute: 'block_public_acls', op: 'equals', value_json: 'true' }, message: 'Block public access' },
      { name: 'bad', description: '', severity: 'low', resource: 'x', projects: [], actions: [], kind: 'deny_if', condition: { attribute: 'a', op: 'matches', value_json: 'not json' }, message: '' },
    ],
    tests: [
      { rule: 'no-public-buckets', resource_type: 'aws_s3_bucket_public_access_block', values_json: '{"block_public_acls": false}', should_fail: true, description: 'open bucket' },
      { rule: 'no-public-buckets', resource_type: 'aws_s3_bucket_public_access_block', values_json: '{"block_public_acls": true}', should_fail: false, description: 'closed bucket' },
      { rule: 'no-public-buckets', resource_type: 'aws_s3_bucket_public_access_block', values_json: '{"block_public_acls": true}', should_fail: true, description: 'a wrong test' },
      { rule: 'missing', resource_type: 'x', values_json: '{}', should_fail: true, description: '' },
    ],
    notes: '',
  });
  assert.deepEqual(d.rules.map(r => r.name), ['no-public-buckets']);
  assert.deepEqual(d.rules[0].require, { attribute: 'block_public_acls', equals: true });
  assert.deepEqual(d.rules[0].projects, ['prod/**']);
  assert.match(d.error!, /bad: the condition's value is not JSON/);
  assert.deepEqual(d.tests.map(t => t.passed), [true, true, false, false]);
  assert.equal(d.tests[3].error, 'no such rule');
});

test('teriac ask: free text, every line, and listed in help when on', () => {
  const r = parseCommand('teriac ask why is the subnet replaced?\nand is it safe?', ['teriac']);
  assert.ok(r?.ok);
  assert.equal(r.ok && r.command.question, 'why is the subnet replaced?\nand is it safe?');
  const empty = parseCommand('@teriac ask', ['teriac']);
  assert.ok(empty && !empty.ok && /Ask a question/.test(empty.error));
  assert.match(helpText('teriac', false, true), /teriac ask <question>/);
  assert.doesNotMatch(helpText('teriac', false, false), /ask/);
});

test('rendering: labelled as AI, reviews and fixes', () => {
  const run = (ai: Run['ai']) => ({ ai } as Run);
  const review = aiLines(run({ kind: 'review', model: 'claude-opus-5-5', summary: 'Replaces the DB.', findings: [{ address: 'aws_db_instance.main', severity: 'high', title: 'Data loss', why: 'No final snapshot.' }] })).join('\n');
  assert.match(review, /🤖 \*\*AI review\*\* <sub>claude-opus-5-5 · advisory, check it yourself<\/sub>/);
  assert.match(review, /> Replaces the DB\.\n- 🔴 \*\*Data loss\*\* · `aws_db_instance\.main` · No final snapshot\./);
  const fix = aiLines(run({ kind: 'fix', model: 'm', cause: 'Missing variable.', fixes: [{ path: 'main.tf', startLine: 3, endLine: 4, replacement: 'variable "x" {}', why: 'declare it' }] })).join('\n');
  assert.match(fix, /🤖 \*\*AI: why it failed\*\*/);
  assert.match(fix, /\*\*Suggested fix\*\* · `main\.tf` lines 3–4: declare it\n```hcl\nvariable "x" \{\}\n```/);
  assert.deepEqual(aiLines(run(null)), []);
});

test('drift: the AI adopts, reverts or leaves what the rules could not edit', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-ai-drift-'));
  mkdirSync(join(tmp, 'envs/prod'), { recursive: true });
  writeFileSync(join(tmp, 'envs/prod/main.tf'), [
    'resource "aws_instance" "web" {',
    '  instance_type = "t3.small"',
    '  tags = { Name = "web" }',
    '}',
    '',
    'resource "aws_security_group" "ssh" {',
    '  cidr = "10.0.0.0/8"',
    '}',
    '',
  ].join('\n'));
  try {
    const plan = { resource_drift: [
      { address: 'aws_instance.web', change: { actions: ['update'], before: { instance_type: 't3.small', tags: { Name: 'web' } }, after: { instance_type: 't3.large', tags: { Name: 'web', Team: 'core' } } } },
      { address: 'aws_security_group.ssh', change: { actions: ['update'], before: { cidr: ['10.0.0.0/8'] }, after: { cidr: ['0.0.0.0/0'] } } },
    ] };
    const fix = planDriftFix(tmp, 'envs/prod', plan);
    assert.equal(fix.edits.length, 1, 'instance_type is mechanical');
    const { call, sent } = fake({ decisions: [
      { address: 'aws_instance.web', decision: 'adopt', why: 'A team tag was added on purpose.', edits: [{ path: 'envs/prod/main.tf', start_line: 3, end_line: 3, replacement: '  tags = { Name = "web", Team = "core" }' }] },
      { address: 'aws_security_group.ssh', decision: 'revert', why: 'SSH opened to the internet.', edits: [{ path: 'envs/prod/main.tf', start_line: 7, end_line: 7, replacement: 'ignored' }] },
    ] });
    const out = await aiDriftFix(new Ai(cfg, { call }), tmp, 'envs/prod', 'envs/prod', plan, fix);
    const text = out.files.find(f => f.path === 'envs/prod/main.tf')!.content;
    assert.match(text, /instance_type = "t3\.large"/, 'the mechanical edit stays');
    assert.match(text, /tags = \{ Name = "web", Team = "core" \}/, 'the adopt edit is made');
    assert.match(text, /cidr = "10\.0\.0\.0\/8"/, 'a revert changes no code');
    assert.match(JSON.stringify(sent[0]), /t3\.large/, 'the AI sees the file after the mechanical edits');
    assert.equal(out.manual.length, 0, 'both were decided');
    const body = driftFixBody('envs/prod', 'main', out, 'nightly');
    assert.match(body, /\*\*🤖 Updated in code by AI\*\* <sub>claude-opus-5-5 · check each change<\/sub>\n- `aws_instance\.web`: A team tag was added on purpose\./);
    assert.match(body, /\*\*🤖 Left for applying back\*\*[^\n]*\n- `aws_security_group\.ssh`: SSH opened to the internet\./);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
