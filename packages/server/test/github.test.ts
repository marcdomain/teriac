import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, createVerify } from 'node:crypto';
import { GitHubAdapter, appJwt, verifySignature } from '../src/vcs/github.ts';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const cfg = { appId: '123', privateKey: pem, webhookSecret: 'whsec-test-123', apiUrl: 'https://api.github.com', host: 'github.com' };

test('webhook signatures', () => {
  const body = Buffer.from('{"a":1}');
  const sig = `sha256=${createHmac('sha256', cfg.webhookSecret).update(body).digest('hex')}`;
  assert.equal(verifySignature(cfg.webhookSecret, body, sig), true);
  assert.equal(verifySignature(cfg.webhookSecret, Buffer.from('{"a":2}'), sig), false);
  assert.equal(verifySignature(cfg.webhookSecret, body, undefined), false);
  assert.equal(verifySignature(cfg.webhookSecret, body, 'sha256=00'), false);
});

test('app JWT is RS256-signed with a short expiry', () => {
  const jwt = appJwt('123', pem, 1_000_000);
  const [h, p, s] = jwt.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url').toString()), { alg: 'RS256', typ: 'JWT' });
  assert.deepEqual(JSON.parse(Buffer.from(p, 'base64url').toString()), { iat: 999_940, exp: 1_000_540, iss: '123' });
  const v = createVerify('RSA-SHA256');
  v.update(`${h}.${p}`);
  assert.ok(v.verify(publicKey, Buffer.from(s, 'base64url')));
});

const gh = new GitHubAdapter(cfg);
const repository = { name: 'infra', full_name: 'acme/infra', owner: { login: 'acme' }, clone_url: 'https://github.com/acme/infra.git' };
const pull = {
  number: 7, title: 't', html_url: 'u', user: { login: 'bob' }, draft: false, merged: false,
  head: { sha: 'abc', ref: 'feat', repo: { full_name: 'acme/infra' } }, base: { ref: 'main', repo: { full_name: 'acme/infra' } },
};

test('parses PR, comment and Apply-button events', () => {
  const pr = gh.parse({ 'x-github-event': 'pull_request' }, { action: 'synchronize', repository, installation: { id: 9 }, pull_request: pull });
  assert.equal(pr.kind, 'pr_updated');
  assert.equal(pr.kind === 'pr_updated' && pr.repo.installationId, 9);

  const c = gh.parse({ 'x-github-event': 'issue_comment' }, {
    action: 'created', repository, issue: { number: 7, pull_request: {} }, comment: { id: 55, body: 'teriac plan', user: { login: 'bob', type: 'User' } },
  });
  assert.deepEqual(c.kind === 'comment' && [c.prNumber, c.commentId, c.author, c.body], [7, '55', 'bob', 'teriac plan']);

  const bot = gh.parse({ 'x-github-event': 'issue_comment' }, {
    action: 'created', repository, issue: { number: 7, pull_request: {} }, comment: { id: 56, body: 'teriac apply', user: { login: 'x[bot]', type: 'Bot' } },
  });
  assert.equal(bot.kind, 'ignored');

  const button = gh.parse({ 'x-github-event': 'check_run' }, {
    action: 'requested_action', repository, requested_action: { identifier: 'apply' }, sender: { login: 'erin' },
    check_run: { external_id: 'envs/prod', pull_requests: [{ number: 7 }] },
  });
  assert.deepEqual(button.kind === 'apply_button' && [button.prNumber, button.project, button.user], [7, 'envs/prod', 'erin']);

  const fork = gh.parse({ 'x-github-event': 'pull_request' }, {
    action: 'opened', repository, pull_request: { ...pull, head: { ...pull.head, repo: { full_name: 'stranger/infra' } } },
  });
  assert.equal(fork.kind === 'pr_opened' && fork.pr.fromFork, true);
});

test('permission lookup maps GitHub roles and caches', async () => {
  let calls = 0;
  const fake: typeof fetch = async (url) => {
    const u = String(url);
    if (u.endsWith('/access_tokens')) return new Response(JSON.stringify({ token: 'ghs_faketoken', expires_at: new Date(Date.now() + 3600e3).toISOString() }));
    calls++;
    if (u.includes('/collaborators/erin/')) return new Response(JSON.stringify({ permission: 'write', role_name: 'maintain' }));
    if (u.includes('/memberships/carol')) return new Response(JSON.stringify({ state: 'active' }));
    return new Response('{"message":"Not Found"}', { status: 404 });
  };
  const a = new GitHubAdapter(cfg, fake);
  const repo = { platform: 'github' as const, host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 };
  assert.equal(await a.userPermission(repo, 'erin'), 'maintain');
  assert.equal(await a.userPermission(repo, 'erin'), 'maintain');
  assert.equal(await a.userPermission(repo, 'nobody'), 'none');
  assert.equal(await a.inTeam(repo, 'platform-admins', 'carol'), true);
  assert.equal(await a.inTeam(repo, 'other-org/platform-admins', 'dave'), false);
  assert.equal(calls, 4); // erin's second lookup came from the cache
});

test('approvals on later pages of reviews are found (pagination)', async () => {
  // 250 reviews over 3 pages; the only approval of the head commit is on page 3.
  const all = Array.from({ length: 250 }, (_, i) => ({ id: i, user: { login: `u${i}` }, state: 'COMMENTED', commit_id: 'head' }));
  all[245] = { id: 245, user: { login: 'carol' }, state: 'APPROVED', commit_id: 'head' };
  const fake: typeof fetch = async (url) => {
    const u = new URL(String(url));
    if (u.pathname.endsWith('/access_tokens')) return new Response(JSON.stringify({ token: 'ghs_x', expires_at: new Date(Date.now() + 3600e3).toISOString() }));
    const page = Number(u.searchParams.get('page') ?? 1);
    const items = all.slice((page - 1) * 100, page * 100);
    const next = page < 3 ? `<https://api.github.com/repos/acme/infra/pulls/7/reviews?per_page=100&page=${page + 1}>; rel="next"` : '';
    return new Response(JSON.stringify(items), { headers: next ? { link: next } : {} });
  };
  const a = new GitHubAdapter(cfg, fake);
  const repo = { platform: 'github' as const, host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 };
  const reviews = await a.reviews(repo, 7);
  assert.equal(reviews.length, 250);
  assert.deepEqual(reviews.filter(r => r.state === 'approved').map(r => r.user), ['carol']);
});

test('the single updating comment is edited by id, without listing comments', async () => {
  const calls: string[] = [];
  const fake: typeof fetch = async (url, init) => {
    const u = String(url);
    calls.push(`${init?.method ?? 'GET'} ${new URL(u).pathname}`);
    if (u.endsWith('/access_tokens')) return new Response(JSON.stringify({ token: 'ghs_x', expires_at: new Date(Date.now() + 3600e3).toISOString() }));
    if (u.includes('/issues/comments/111')) return new Response(JSON.stringify({ id: 111, html_url: 'https://github.com/c/111' }));
    return new Response('{}', { status: 404 });
  };
  const a = new GitHubAdapter(cfg, fake);
  const repo = { platform: 'github' as const, host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 };
  assert.deepEqual(await a.upsertComment(repo, 7, 'M', 'body', '111'), { id: '111', url: 'https://github.com/c/111' });
  assert.deepEqual(calls.filter(c => !c.includes('access_tokens')), ['PATCH /repos/acme/infra/issues/comments/111']);
});

test('webhook: someone else editing a bot comment is reported; the bot editing its own is not', async () => {
  const base = { repository, issue: { number: 7, pull_request: {} } };
  const ev = (sender: string): any => gh.parse({ 'x-github-event': 'issue_comment' }, {
    ...base, action: 'edited', sender: { login: sender }, comment: { id: 5, body: 'x', user: { login: 'teriac[bot]', type: 'Bot' } },
  });
  assert.deepEqual({ ...ev('mallory'), repo: undefined }, { kind: 'bot_comment_changed', repo: undefined, prNumber: 7, commentId: '5', by: 'mallory', change: 'edited', body: 'x' });
  assert.equal(ev('teriac[bot]').kind, 'ignored');
});

test('a repo with no installation id (dashboard, schedules) finds it once and reuses it', async () => {
  const seen: string[] = [];
  const fake: typeof fetch = async (url) => {
    const u = String(url);
    seen.push(u.replace('https://api.github.com', ''));
    if (u.endsWith('/repos/acme/infra/installation')) return new Response(JSON.stringify({ id: 77 }));
    if (u.endsWith('/app/installations/77/access_tokens')) return new Response(JSON.stringify({ token: 'ghs_x', expires_at: new Date(Date.now() + 3600e3).toISOString() }));
    if (u.includes('/issues/1/comments')) return new Response(JSON.stringify({ id: 5, html_url: 'u' }), { status: 201 });
    return new Response('{"message":"Not Found"}', { status: 404 });
  };
  const a = new GitHubAdapter(cfg, fake);
  const repo = { platform: 'github' as const, host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '' };
  assert.equal(await a.comment(repo, 1, 'hi'), '5');
  assert.equal(await a.comment(repo, 1, 'again'), '5');
  assert.equal(seen.filter(u => u.endsWith('/installation')).length, 1, 'looked up once');
  // Not installed on the repo: a clear error.
  const none = new GitHubAdapter(cfg, async () => new Response('{}', { status: 404 }));
  await assert.rejects(none.comment({ ...repo, fullName: 'acme/other' }, 1, 'x'), /no GitHub App installation for acme\/other \(HTTP 404\); is the App installed on it\?/);
});

test('download token: from any installation of the App, github.com only', async () => {
  let body = '';
  const fake: typeof fetch = async (url, init) => {
    const u = String(url);
    if (u.endsWith('/app/installations?per_page=1')) return new Response(JSON.stringify([{ id: 31, account: { login: 'acme' } }]));
    if (u.endsWith('/app/installations/31/access_tokens')) { body = String(init?.body ?? ''); return new Response(JSON.stringify({ token: 'ghs_dl', expires_at: new Date(Date.now() + 3600e3).toISOString() })); }
    return new Response('{}', { status: 404 });
  };
  assert.equal(await new GitHubAdapter(cfg, fake).downloadToken(), 'ghs_dl');
  assert.deepEqual(JSON.parse(body), { permissions: { metadata: 'read' } }, 'no access to any repository');
  assert.equal(await new GitHubAdapter({ ...cfg, host: 'github.acme.internal', apiUrl: 'https://github.acme.internal/api/v3' }, fake).downloadToken(), null, 'Enterprise App: not for github.com');
  const none: typeof fetch = async () => new Response('[]');
  assert.equal(await new GitHubAdapter(cfg, none).downloadToken(), null, 'not installed anywhere');
});

test('module downloads get a read-only token, cached apart from the full one', async () => {
  const bodies: (string | null)[] = [];
  let n = 0;
  const fake: typeof fetch = async (url, init) => {
    const u = String(url);
    if (u.endsWith('/installation')) return new Response(JSON.stringify({ id: 5 }));
    if (u.endsWith('/app/installations/5/access_tokens')) {
      bodies.push(init?.body ? String(init.body) : null);
      return new Response(JSON.stringify({ token: `ghs_${++n}`, expires_at: new Date(Date.now() + 3600e3).toISOString() }));
    }
    return new Response('{}', { status: 404 });
  };
  const repo = { platform: 'github' as const, host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: 'https://github.com/acme/infra.git', installationId: 5 };
  const a = new GitHubAdapter(cfg, fake);
  const m = (await a.moduleAuth(repo))!;
  assert.equal(m.url, 'https://github.com/');
  assert.equal(Buffer.from(m.extraHeader!.replace('Authorization: Basic ', ''), 'base64').toString(), 'x-access-token:ghs_1');
  assert.deepEqual(JSON.parse(bodies[0]!), { permissions: { contents: 'read', metadata: 'read' } });
  await a.moduleAuth(repo);
  assert.equal(bodies.length, 1, 'cached');
  const clone = await a.cloneAuth(repo);
  assert.equal(bodies.length, 2, 'the full token is a separate one');
  assert.equal(bodies[1], null, 'with all of the App permissions');
  assert.notEqual(clone.extraHeader, m.extraHeader);
});

test('git settings for module downloads: header for the host only; your own settings win', async () => {
  const { gitAuthEnv } = await import('../src/runner.ts');
  const auth = { url: 'https://github.com/', extraHeader: 'Authorization: Basic abc' };
  assert.deepEqual(gitAuthEnv({}, auth), { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader', GIT_CONFIG_VALUE_0: 'Authorization: Basic abc' });
  assert.deepEqual(gitAuthEnv({ GIT_CONFIG_COUNT: '1' }, auth), {}, 'GIT_CONFIG_* from extraEnv takes over');
  assert.deepEqual(gitAuthEnv({}, null), {});
  assert.deepEqual(gitAuthEnv({}, { url: 'https://ghe.acme.dev/api/v3', extraHeader: 'h' }).GIT_CONFIG_KEY_0, 'http.https://ghe.acme.dev/.extraheader');
  assert.deepEqual(gitAuthEnv({}, { url: 'git://x/y', extraHeader: 'h' }), {});
});

// ---- key rotation ----------------------------------------------------------------
const second = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pemNext = second.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString();
const signedBy = (auth: string, pub: typeof publicKey) => {
  const [h, p, s] = auth.replace('Bearer ', '').split('.');
  return !!s && createVerify('RSA-SHA256').update(`${h}.${p}`).verify(pub, Buffer.from(s, 'base64url'));
};

test('rotation: when GitHub refuses the current key, the next one signs in, and is used first from then on', async () => {
  let accept = publicKey;           // GitHub has both keys; then the old one is deleted
  const calls: string[] = [];
  let n = 0;
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const auth = String((init.headers as Record<string, string>).Authorization);
    if (url.includes('/access_tokens')) {
      const ok = signedBy(auth, accept);
      calls.push(signedBy(auth, publicKey) ? 'old' : 'next');
      return ok ? Response.json({ token: `ghs_${++n}`, expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 }) : new Response('{"message":"bad credentials"}', { status: 401 });
    }
    return Response.json({ ok: true, auth });
  }) as typeof fetch;
  const a = new GitHubAdapter({ ...cfg, secrets: () => ({ keys: [pem, pemNext], webhookSecrets: [cfg.webhookSecret] }) }, fetchImpl);
  const repo = { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 } as any;
  await (a as any).installationToken(repo);
  assert.deepEqual(calls, ['old']);
  accept = second.publicKey;        // the old key is deleted in GitHub
  (a as any).tokens.clear();
  const t = await (a as any).installationToken(repo, { metadata: 'read' });
  assert.equal(t, 'ghs_2');
  assert.deepEqual(calls, ['old', 'old', 'next']);
  (a as any).tokens.clear();
  await (a as any).installationToken(repo);
  assert.deepEqual(calls.slice(3), ['next'], 'the key that worked is tried first');
});

test('rotation: a running job whose token is refused gets a fresh one and carries on', async () => {
  let n = 0;
  const seen: string[] = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    if (url.includes('/access_tokens')) return Response.json({ token: `ghs_${++n}`, expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 });
    const auth = String((init.headers as Record<string, string>).Authorization);
    seen.push(auth);
    return auth === 'Bearer ghs_1' ? new Response('{"message":"Bad credentials"}', { status: 401 }) : Response.json({ id: 1 });
  }) as typeof fetch;
  const a = new GitHubAdapter(cfg, fetchImpl);
  const repo = { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 } as any;
  const id = await a.comment(repo, 7, 'hello');
  assert.equal(id, '1');
  assert.deepEqual(seen, ['Bearer ghs_1', 'Bearer ghs_2']);
});

test('rotation: webhooks signed with either secret are accepted; the JWT names the client ID when set', () => {
  const a = new GitHubAdapter({ ...cfg, clientId: 'Iv23liABC', secrets: () => ({ keys: [pem], webhookSecrets: ['old-secret', 'new-secret'] }) });
  const body = Buffer.from('{}');
  const sig = (s: string) => `sha256=${createHmac('sha256', s).update(body).digest('hex')}`;
  assert.equal(a.verify({ 'x-hub-signature-256': sig('old-secret') }, body), true);
  assert.equal(a.verify({ 'x-hub-signature-256': sig('new-secret') }, body), true);
  assert.equal(a.verify({ 'x-hub-signature-256': sig('other') }, body), false);
});

test('rotation: key files are re-read when they change, without a restart', async () => {
  const { mkdtempSync, writeFileSync, rmSync, utimesSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const { loadConfig } = await import('../src/config.ts');
  const dir = mkdtempSync(join(tmpdir(), 'teriac-keys-'));
  try {
    writeFileSync(join(dir, 'key'), pem);
    writeFileSync(join(dir, 'hook'), 'old-secret');
    const c = loadConfig({
      TERIAC_GITHUB_APP_ID: '1', TERIAC_GITHUB_PRIVATE_KEY_FILE: join(dir, 'key'), TERIAC_GITHUB_PRIVATE_KEY_NEXT_FILE: join(dir, 'key-next'),
      TERIAC_GITHUB_WEBHOOK_SECRET_FILE: join(dir, 'hook'), TERIAC_GITHUB_WEBHOOK_SECRET_NEXT_FILE: join(dir, 'hook-next'),
      TERIAC_REPO_ALLOWLIST: 'github.com/acme/*', TERIAC_DATA_DIR: dir,
    });
    assert.deepEqual(c.github!.secrets!(), { keys: [pem.trim()], webhookSecrets: ['old-secret'] }, 'no next files yet: fine');
    writeFileSync(join(dir, 'key-next'), pemNext);
    writeFileSync(join(dir, 'hook-next'), 'new-secret');
    assert.deepEqual(c.github!.secrets!(), { keys: [pem.trim(), pemNext.trim()], webhookSecrets: ['old-secret', 'new-secret'] });
    // Rotation done: the next key becomes the key.
    writeFileSync(join(dir, 'key'), pemNext);
    utimesSync(join(dir, 'key'), new Date(), new Date(Date.now() + 5000));
    rmSync(join(dir, 'key-next'));
    assert.deepEqual(c.github!.secrets!().keys, [pemNext.trim()]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('after a restart: failed webhooks since then are resent once; older ones are only counted', async () => {
  const now = new Date('2026-11-15T12:00:00Z');
  const at = (minAgo: number) => new Date(now.getTime() - minAgo * 60_000).toISOString();
  const deliveries = [
    { id: 1, guid: 'a', delivered_at: at(5), status_code: 0 },     // failed during the restart
    { id: 2, guid: 'b', delivered_at: at(6), status_code: 502 },   // failed, then
    { id: 3, guid: 'b', delivered_at: at(4), status_code: 202 },   // ...a later attempt succeeded
    { id: 4, guid: 'c', delivered_at: at(3), status_code: 202 },   // fine
    { id: 5, guid: 'd', delivered_at: at(180), status_code: 0 },   // failed 3 hours ago: too old
  ];
  const posted: string[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (init?.method === 'POST') { posted.push(url); return new Response('', { status: 202 }); }
    return Response.json(deliveries);
  }) as typeof fetch;
  const a = new GitHubAdapter(cfg, fetchImpl);
  const r = await a.redeliverMissed(new Date(now.getTime() - 60 * 60_000), now);
  assert.deepEqual(r, { redelivered: 1, tooOld: 1 });
  assert.deepEqual(posted, ['https://api.github.com/app/hook/deliveries/1/attempts']);
});

test('automerge without Contents: write says which permission to add', async () => {
  const fetchImpl = (async (url: string) => {
    if (url.includes('/access_tokens')) return Response.json({ token: 'ghs_x', expires_at: new Date(Date.now() + 3_600_000).toISOString() }, { status: 201 });
    return new Response('{"message":"Resource not accessible by integration"}', { status: 403 });
  }) as typeof fetch;
  const a = new GitHubAdapter(cfg, fetchImpl);
  const repo = { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '', installationId: 9 } as any;
  assert.deepEqual(await a.mergePullRequest(repo, 7, 'squash', 'abc'), { ok: false, message: 'the GitHub App needs Contents: Read & write to merge pull requests (App settings → Permissions)' });
});
