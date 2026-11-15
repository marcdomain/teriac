// Log expiry after apply, and reminders for PRs applied but not merged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Housekeeper } from '../src/housekeeping.ts';
import { Store } from '../src/store.ts';

const HOUR = 3_600_000;
const REPO = 'github.com/acme/infra';

const seed = (store: Store, pr: number, appliedHoursAgo: number, now: Date) => {
  const db = (store as any).db;
  const at = (h: number) => new Date(now.getTime() - h * HOUR).toISOString();
  const plan = store.startRun({ repo: REPO, pr, project: 'envs/dev', workspace: 'default', kind: 'plan', headSha: 'abc', user: 'bob' });
  store.finishRun(plan, { status: 'success', engine: 'terraform 1.9.8', summary: '{"add":1}', output: 'Plan: 1 to add.', hasChanges: true });
  const apply = store.startRun({ repo: REPO, pr, project: 'envs/dev', workspace: 'default', kind: 'apply', headSha: 'abc', user: 'erin' });
  store.finishRun(apply, { status: 'success', engine: 'terraform 1.9.8', output: 'Apply complete!' });
  db.prepare('UPDATE runs SET started_at = ?, finished_at = ? WHERE id = ?').run(at(appliedHoursAgo + 1), at(appliedHoursAgo + 1), plan);
  db.prepare('UPDATE runs SET started_at = ?, finished_at = ? WHERE id = ?').run(at(appliedHoursAgo), at(appliedHoursAgo), apply);
  return { plan, apply };
};

const config = (repo: Record<string, unknown>, server: Record<string, unknown> = {}) => ({
  repos: [{ id: 'github.com/acme/*', ...repo }], channels: { ops: { type: 'webhook', webhook_url_env: 'HOOK' } }, people: [], ...server,
}) as any;

test('logs are cleared N days after the PR\'s last apply; everything else stays', async () => {
  const now = new Date('2026-11-20T12:00:00Z');
  const store = new Store(':memory:');
  const old = seed(store, 1, 8 * 24, now);   // applied 8 days ago
  const recent = seed(store, 2, 2 * 24, now); // 2 days ago
  const hk = new Housekeeper({ config: config({}, { logRetentionDays: 7 }), store, adapterFor: () => undefined });
  const r = await hk.tick(now);
  assert.equal(r.expired, 2, 'both runs of the old PR');
  const p = store.getRun(old.plan)!;
  assert.deepEqual([p.output, p.outputExpiredAt, p.summary, p.user], ['', now.toISOString(), '{"add":1}', 'bob']);
  assert.equal(store.getRun(recent.plan)!.output, 'Plan: 1 to add.', 'not yet');
  assert.equal((await hk.tick(now)).expired, 0, 'done once');
  // A repo can keep its logs for less (or more) time than the server.
  const store2 = new Store(':memory:');
  const r2 = seed(store2, 3, 2 * 24, now);
  await new Housekeeper({ config: config({ log_retention_days: 1 }, { logRetentionDays: 30 }), store: store2, adapterFor: () => undefined }).tick(now);
  assert.equal(store2.getRun(r2.apply)!.output, '');
});

test('applied but not merged after N hours: one short comment to whoever applied, and chat', async () => {
  const now = new Date('2026-11-20T12:00:00Z');
  const store = new Store(':memory:');
  seed(store, 1, 30, now);                                      // still open
  seed(store, 2, 30, now);
  store.markPrClosed(REPO, 2, true);                            // merged (its event arrived)
  seed(store, 3, 2, now);                                       // open, but applied only 2 hours ago
  seed(store, 4, 30, now);                                      // merged, but the event was missed
  const comments: { pr: number; body: string }[] = [];
  const sent: any[] = [];
  const adapter = {
    platform: 'github',
    comment: async (_r: any, pr: number, body: string) => { comments.push({ pr, body }); return '1'; },
    getPullRequest: async (_r: any, pr: number) => ({ number: pr, open: pr !== 4 }),
  } as any;
  const fetchImpl = (async (_u: string, init: RequestInit) => { sent.push(JSON.parse(String(init.body))); return new Response('ok'); }) as typeof fetch;
  const hk = new Housekeeper({ config: config({ remind_unmerged: { after_hours: 24, notify: ['ops'] } }), store, adapterFor: () => adapter, env: { HOOK: 'https://hook.test' }, fetchImpl });
  assert.equal((await hk.tick(now)).reminded, 1);
  assert.deepEqual(comments.map(c => c.pr), [1]);
  assert.equal(comments[0].body, "⏰ @erin applied `envs/dev` 30 hours ago, but this pull request isn't merged yet. Until it is, the base branch doesn't match what's deployed. Merge it, or revert the change and apply again.");
  assert.equal(sent.length, 1);
  assert.equal(sent[0].title, '⏰ Applied but not merged: acme/infra #1');
  assert.match(sent[0].text ?? JSON.stringify(sent[0]), /`envs\/dev` applied by erin 30 hours ago/);
  assert.equal((await hk.tick(new Date(now.getTime() + HOUR))).reminded, 0, 'once per apply');
});

test('settings are checked at start-up', async () => {
  const { parseServerPolicy } = await import('../src/config.ts');
  assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    remind_unmerged: { notify: [ops] }\n'), /needs after_hours/);
  assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    remind_unmerged: { after_hours: 24, notify: [nope] }\n'), /no channel named "nope"/);
  assert.throws(() => parseServerPolicy('repos:\n  - id: github.com/a/b\n    log_retention_days: 0\n'), /whole number of days/);
});
