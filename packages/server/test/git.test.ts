import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { checkout, checkoutBranch } from '../src/git.ts';

test('recovers a checkout that was interrupted before the remote was added', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-git-'));
  try {
    const origin = join(tmp, 'origin');
    mkdirSync(origin);
    const g = (...a: string[]) => execFileSync('git', a, { cwd: origin, encoding: 'utf-8' }).trim();
    g('init', '-q', '-b', 'main');
    g('config', 'uploadpack.allowAnySHA1InWant', 'true');
    g('config', 'uploadpack.allowFilter', 'true');
    writeFileSync(join(origin, 'main.tf'), 'v1\n');
    g('add', '-A');
    g('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'v1');
    const sha = g('rev-parse', 'HEAD');

    // A half-made checkout: `git init` ran, the process died before `remote add`.
    for (const [name, fn] of [['pr', () => checkout(join(tmp, 'pr'), { url: origin }, sha)], ['branch', () => checkoutBranch(join(tmp, 'branch'), { url: origin }, 'main')]] as const) {
      mkdirSync(join(tmp, name));
      execFileSync('git', ['init', '-q'], { cwd: join(tmp, name) });
      await fn();
      assert.equal(readFileSync(join(tmp, name, 'main.tf'), 'utf-8'), 'v1\n');
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('a PR checkout keeps local state files between runs, but removes other leftovers', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-git-'));
  try {
    const origin = join(tmp, 'origin');
    mkdirSync(join(origin, 'infra'), { recursive: true });
    const g = (...a: string[]) => execFileSync('git', a, { cwd: origin, encoding: 'utf-8' }).trim();
    g('init', '-q', '-b', 'main');
    g('config', 'uploadpack.allowAnySHA1InWant', 'true');
    writeFileSync(join(origin, 'infra/main.tf'), 'v1\n');
    g('add', '-A');
    g('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'v1');
    const sha = g('rev-parse', 'HEAD');
    const work = join(tmp, 'work');
    await checkout(work, { url: origin }, sha);
    writeFileSync(join(work, 'infra/terraform.tfstate'), '{"serial":3}');
    writeFileSync(join(work, 'infra/leftover.txt'), 'x');
    await checkout(work, { url: origin }, sha);
    assert.equal(readFileSync(join(work, 'infra/terraform.tfstate'), 'utf-8'), '{"serial":3}');
    assert.throws(() => readFileSync(join(work, 'infra/leftover.txt')));
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('merge checkout: the PR merged into its base branch, only for this exact commit', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'teriac-merge-'));
  try {
    const origin = join(tmp, 'origin');
    mkdirSync(origin);
    const g = (...a: string[]) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd: origin, encoding: 'utf-8' }).trim();
    g('init', '-q', '-b', 'main');
    g('config', 'uploadpack.allowAnySHA1InWant', 'true');
    writeFileSync(join(origin, 'main.tf'), 'v1\n');
    g('add', '-A'); g('commit', '-qm', 'v1');
    g('checkout', '-q', '-b', 'feature');
    writeFileSync(join(origin, 'app.tf'), 'feature\n');
    g('add', '-A'); g('commit', '-qm', 'feature');
    const head = g('rev-parse', 'HEAD');
    g('checkout', '-q', 'main');
    writeFileSync(join(origin, 'network.tf'), 'added on main later\n');
    g('add', '-A'); g('commit', '-qm', 'main moved on');
    // What GitHub prepares: refs/pull/1/head and a test merge in refs/pull/1/merge.
    g('update-ref', 'refs/pull/1/head', head);
    g('merge', '-q', '--no-ff', '--no-edit', 'feature');
    g('update-ref', 'refs/pull/1/merge', g('rev-parse', 'HEAD'));
    g('reset', '-q', '--hard', 'HEAD~1');

    const work = join(tmp, 'work');
    await checkout(work, { url: origin }, head, 'refs/pull/1/head', 'refs/pull/1/merge');
    assert.equal(readFileSync(join(work, 'app.tf'), 'utf-8'), 'feature\n', 'the PR\'s change');
    assert.equal(readFileSync(join(work, 'network.tf'), 'utf-8'), 'added on main later\n', 'and what main has now');

    // A merge of an older commit (GitHub hasn't caught up) or no merge at all is refused.
    await assert.rejects(checkout(join(tmp, 'w2'), { url: origin }, 'f'.repeat(40), undefined, 'refs/pull/1/merge', 1), /can't be merged into its base branch cleanly/);
    await assert.rejects(checkout(join(tmp, 'w3'), { url: origin }, head, undefined, 'refs/pull/9/merge', 1), /can't be merged/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
