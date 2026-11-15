import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.ts';

test('metrics for a custom date range: only runs inside it, "to" exclusive', () => {
  const dir = mkdtempSync(join(tmpdir(), 'teriac-stats-'));
  const store = new Store(join(dir, 'db.sqlite'));
  try {
    const at = (iso: string, kind: 'plan' | 'apply', usage?: object, applied?: object) => {
      const id = store.startRun({ repo: 'github.com/acme/infra', pr: 1, project: 'p', workspace: 'default', kind, headSha: 'abc', user: 'bob' });
      store.finishRun(id, { status: 'success', output: '', usage: usage ?? null, applied: applied ?? null });
      (store as any).db.prepare('UPDATE runs SET started_at = ?, finished_at = ? WHERE id = ?').run(iso, iso, id);
    };
    at('2026-10-01T10:00:00.000Z', 'plan');
    at('2026-10-05T10:00:00.000Z', 'plan', { cpuSeconds: 3, peakMemory: 100, peakProcesses: 2 });
    at('2026-10-06T10:00:00.000Z', 'apply', undefined, { added: 2, changed: 1, destroyed: 0 });
    at('2026-10-10T00:00:00.000Z', 'plan'); // exactly "to": excluded
    const s = store.stats('2026-10-05T00:00:00.000Z', '2026-10-10T00:00:00.000Z');
    assert.equal(s.totals.runs, 2);
    assert.equal(s.totals.applies, 1);
    assert.deepEqual(s.resources, { added: 2, changed: 1, destroyed: 0 });
    assert.equal(s.usage.runs, 1);
    assert.deepEqual(s.daily.map(d => d.day), ['2026-10-05', '2026-10-06']);
    // Open-ended: everything from "from" on.
    assert.equal(store.stats('2026-10-05T00:00:00.000Z').totals.runs, 3);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('usage: measured on Linux; a command too fast to sample is reported as quick', async () => {
  const { UsageSampler, combineUsage, usageSupported } = await import('../src/usage.ts');
  const { spawn } = await import('node:child_process');
  const run = (cmd: string) => new Promise<any>((resolve) => {
    const c = spawn('sh', ['-c', cmd]);
    const s = new UsageSampler(c.pid!);
    c.on('close', () => resolve(s.stop()));
  });
  if (!usageSupported()) {
    assert.equal(await run('true'), null, 'nothing to measure with off Linux');
    return;
  }
  const slow = await run('i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done');
  assert.ok(slow.peakMemory > 0 && slow.peakProcesses >= 1 && !slow.quick);
  assert.equal(combineUsage({ cpuSeconds: 0, peakMemory: 0, peakProcesses: 1, quick: true }, slow)!.quick, undefined);
});

test('per-repo numbers, everyone (not just the top 10), and waiting times', async () => {
  const { Store } = await import('../src/store.ts');
  const store = new Store(':memory:');
  const db = (store as any).db;
  const t = (min: number) => new Date(Date.parse('2026-11-10T10:00:00Z') + min * 60_000).toISOString();
  const run = (repo: string, user: string, kind: 'plan' | 'apply', at: number, endMin: number, extra: Record<string, unknown> = {}) => {
    const id = store.startRun({ repo, pr: 1, project: 'envs/dev', workspace: 'default', kind, headSha: 'abc', user, queuedMs: 4000 });
    store.finishRun(id, { status: 'success', output: '', hasChanges: kind === 'plan', ...extra });
    db.prepare('UPDATE runs SET started_at = ?, finished_at = ? WHERE id = ?').run(t(at), t(endMin), id);
  };
  for (let i = 0; i < 12; i++) run('github.com/acme/infra', `user${i}`, 'plan', i, i + 1);
  run('github.com/acme/data', 'ada', 'plan', 20, 21);
  run('github.com/acme/data', 'ada', 'apply', 81, 82);   // applied an hour after its plan finished
  const s = store.stats(t(-60), t(600));
  assert.equal(s.people.length, 13, 'everyone');
  assert.deepEqual(s.repos.map((r: any) => [r.repo, r.runs, r.applies]), [['github.com/acme/infra', 12, 0], ['github.com/acme/data', 2, 1]]);
  assert.equal(s.waits.planToApply.count, 1);
  assert.equal(Math.round(s.waits.planToApply.p50!), 3600);
  assert.equal(s.waits.queued.count, 14);
  assert.equal(s.waits.queued.p50, 4);
});
