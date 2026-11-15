// Sign in with GitHub: who gets in, what each person sees (only repos they can see on
// GitHub), who may release locks, re-checks with GitHub, and turning password sign-in off.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { GitHubLogin, hashPassword, type AuthConfig } from '../src/auth.ts';
import { createHttpServer } from '../src/http.ts';
import { Store } from '../src/store.ts';

const INFRA = 'github.com/acme/infra';
const SECRET = 'github.com/acme/secret';

// What each GitHub token can see through the App (GitHub intersects person and App).
const people: Record<string, { login: string; repos: string[] }> = {
  'tok-bob': { login: 'bob', repos: ['acme/infra', 'other/elsewhere'] },  // other/* isn't served here
  'tok-mo': { login: 'mo', repos: ['acme/infra'] },
  'tok-ada': { login: 'ada', repos: ['acme/infra', 'acme/secret'] },
  'tok-eve': { login: 'eve', repos: ['other/elsewhere'] },
};
const revoked = new Set<string>();
const fakeGitHub = (async (url: string, init?: RequestInit) => {
  const u = new URL(url);
  if (u.pathname === '/login/oauth/access_token') {
    const body = JSON.parse(String(init!.body));
    if (body.client_secret !== 'gh-client-secret' || !body.code_verifier) return Response.json({ error: 'bad_verification_code' });
    return Response.json({ access_token: `tok-${body.code}`, refresh_token: `ref-${body.code}`, expires_in: 28800 });
  }
  const tok = String((init!.headers as Record<string, string>).Authorization).replace('Bearer ', '');
  const who = people[tok];
  if (!who || revoked.has(tok)) return new Response('{"message":"Bad credentials"}', { status: 401 });
  if (u.pathname === '/user') return Response.json({ login: who.login, name: who.login });
  if (u.pathname === '/user/installations') return Response.json({ installations: [{ id: 9 }] });
  if (u.pathname === '/user/installations/9/repositories') return Response.json({ repositories: who.repos.map(full_name => ({ full_name })) });
  return new Response('not found', { status: 404 });
}) as typeof fetch;

const auth: AuthConfig = {
  apiToken: 'api-token-for-tests-1234567890',
  sessionSecret: 's'.repeat(32), sessionHours: 12, secureCookies: false,
  users: [{ username: 'vic', password_hash: hashPassword('pw-vic-123'), role: 'viewer' }],
  github: { clientId: 'Iv23li', clientSecret: 'gh-client-secret', webUrl: 'https://github.com', apiUrl: 'https://api.github.com', host: 'github.com', adminUsers: [], adminTeams: ['acme/sre'], allowedTeams: [] },
};

let srv: Server;
let base: string;
let store: Store;
const unlocked: string[] = [];
const handled: any[] = [];

before(async () => {
  store = new Store(':memory:');
  const run = (repo: string, project: string) => {
    const id = store.startRun({ repo, pr: 1, project, workspace: 'default', kind: 'plan', headSha: 'abc', user: 'bob' });
    store.finishRun(id, { status: 'success', engine: 'terraform 1.9.8', output: `plan of ${repo}`, hasChanges: true });
    return id;
  };
  run(INFRA, 'envs/dev');
  run(SECRET, 'vault');
  store.acquireLock(INFRA, 'envs/dev', 'default', 1, 'bob');
  store.acquireLock(INFRA, 'envs/prod', 'default', 2, 'carol');
  store.acquireLock(SECRET, 'vault', 'default', 3, 'ada');
  const github = new GitHubLogin(auth.github!, 'http://teriac.test', {
    fetchImpl: fakeGitHub,
    serves: k => k.startsWith('github.com/acme/'),
    inTeam: async (_repo, team, login) => team === 'acme/sre' && login === 'ada',
  });
  const adapter = { platform: 'github', userPermission: async (_r: unknown, login: string) => (login === 'mo' ? 'maintain' : 'write') } as any;
  srv = createHttpServer({
    app: { runQueue: null, commandName: 'teriac', handle: async (_a: unknown, e: unknown) => { handled.push(e); }, dashboardUnlock: async (_a: unknown, l: { project: string }) => { unlocked.push(l.project); return true; } } as any,
    store, adapters: { github: adapter }, platforms: { 'github.com': 'github' }, auth, github, ready: () => true,
  });
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
after(() => { srv.close(); store.close(); });

const cookieOf = (res: Response, name: string) => res.headers.getSetCookie().find(c => c.startsWith(`${name}=`))!.split(';')[0];

// The whole browser round trip: teriac → GitHub → back to teriac with a code.
const signIn = async (code: string) => {
  const start = await fetch(`${base}/auth/github/login`, { redirect: 'manual' });
  assert.equal(start.status, 302);
  const to = new URL(start.headers.get('location')!);
  assert.equal(`${to.origin}${to.pathname}`, 'https://github.com/login/oauth/authorize');
  assert.equal(to.searchParams.get('client_id'), 'Iv23li');
  assert.equal(to.searchParams.get('code_challenge_method'), 'S256');
  const back = await fetch(`${base}/auth/github/callback?code=${code}&state=${to.searchParams.get('state')}`, { redirect: 'manual', headers: { Cookie: cookieOf(start, 'teriac_github') } });
  const location = back.headers.get('location')!;
  return { location, cookie: location === '/#overview' ? cookieOf(back, 'teriac_session') : '' };
};
const get = (cookie: string, path: string) => fetch(`${base}${path}`, { headers: { Cookie: cookie } });
const post = (cookie: string, path: string, body: unknown) => fetch(`${base}${path}`, { method: 'POST', headers: { Cookie: cookie, 'X-Requested-With': 'teriac', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('a GitHub viewer sees only the repos they can see on GitHub, everywhere', async () => {
  const { cookie } = await signIn('bob');
  const me = await (await get(cookie, '/api/me')).json();
  assert.deepEqual([me.name, me.role, me.via, me.repos], ['bob', 'viewer', 'github', 1]);
  const runs = await (await get(cookie, '/api/runs')).json();
  assert.deepEqual(runs.map((r: { repo: string }) => r.repo), [INFRA]);
  const secretRun = store.searchRuns({ repo: SECRET }).items[0];
  assert.equal((await get(cookie, `/api/runs/${secretRun.id}`)).status, 404);
  assert.equal((await get(cookie, `/api/runs/${secretRun.id}/live`)).status, 404);
  assert.equal((await (await get(cookie, '/api/runs/search')).json()).total, 1);
  assert.deepEqual((await (await get(cookie, '/api/facets')).json()).repos, [INFRA]);
  assert.deepEqual((await (await get(cookie, '/api/projects')).json()).map((p: { repo: string }) => p.repo), [INFRA]);
  const stats = await (await get(cookie, '/api/stats')).json();
  assert.deepEqual(stats.projects.map((p: { repo: string }) => p.repo), [INFRA]);
  assert.equal(stats.locks.n, 2, 'only the locks of repos they can see');
  const locks = await (await get(cookie, '/api/locks')).json();
  assert.deepEqual(locks.map((l: { project: string; canUnlock: boolean }) => [l.project, l.canUnlock]), [['envs/dev', true], ['envs/prod', false]]);
});

test('locks: your own, or maintain/admin on the repo; never a repo you can\'t see', async () => {
  const bob = (await signIn('bob')).cookie;
  assert.equal((await post(bob, '/api/locks/unlock', { repo: INFRA, project: 'envs/prod' })).status, 403, "carol's lock");
  assert.equal((await post(bob, '/api/locks/unlock', { repo: SECRET, project: 'vault' })).status, 404, 'not even shown');
  assert.equal((await post(bob, '/api/locks/unlock', { repo: INFRA, project: 'envs/dev' })).status, 200, 'his own');
  const mo = (await signIn('mo')).cookie;
  assert.equal((await post(mo, '/api/locks/unlock', { repo: INFRA, project: 'envs/prod' })).status, 200, 'maintain on the repo');
  assert.deepEqual(unlocked, ['envs/dev', 'envs/prod']);
  assert.equal((await post(mo, '/api/applies/pause', { reason: 'x' })).status, 403, 'admin actions stay admin-only');
});

test('admins come from teams and see every repo; people who can see none are turned away', async () => {
  const ada = (await signIn('ada')).cookie;
  const me = await (await get(ada, '/api/me')).json();
  assert.deepEqual([me.role, me.repos], ['admin', null]);
  assert.equal((await (await get(ada, '/api/runs/search')).json()).total, 2);
  const eve = await signIn('eve');
  assert.match(decodeURIComponent(eve.location), /#signin-error=your GitHub account can't see any repository this teriac serves/);
  const bad = await fetch(`${base}/auth/github/callback?code=bob&state=forged`, { redirect: 'manual' });
  assert.match(decodeURIComponent(bad.headers.get('location')!), /sign-in expired/);
});

test('re-checked with GitHub: revoking the App\'s access signs the person out', async () => {
  const { cookie } = await signIn('mo');
  assert.equal((await get(cookie, '/api/me')).status, 200);
  revoked.add('tok-mo');
  const a = store.getAccess('github:mo')!;
  store.setAccess('github:mo', a.repos, a.role, new Date(Date.now() - 11 * 60_000).toISOString()); // last checked 11 minutes ago
  await get(cookie, '/api/me');                       // starts the check
  await new Promise(r => setTimeout(r, 100));
  assert.equal((await get(cookie, '/api/me')).status, 401);
  revoked.delete('tok-mo');
});

test('password sign-in can be turned off; existing password sessions stop working', async () => {
  const pwLogin = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'teriac' }, body: JSON.stringify({ username: 'vic', password: 'pw-vic-123' }) });
  const old = cookieOf(pwLogin, 'teriac_session');
  assert.equal((await get(old, '/api/me')).status, 200);
  auth.passwordLogin = false;
  try {
    const cfg = await (await fetch(`${base}/auth/config`)).json();
    assert.deepEqual([cfg.password, cfg.github], [false, true]);
    const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'teriac' }, body: JSON.stringify({ username: 'vic', password: 'pw-vic-123' }) });
    assert.equal(res.status, 404);
    assert.equal((await get(old, '/api/me')).status, 401);
  } finally { auth.passwordLogin = undefined; }
});

test('API commands: run as a GitHub login, only plan/apply/unlock/cancel, only repos you can see', async () => {
  const bearer = { Authorization: 'Bearer api-token-for-tests-1234567890', 'Content-Type': 'application/json' };
  const call = (headers: Record<string, string>, body: unknown) => fetch(`${base}/api/commands`, { method: 'POST', headers, body: JSON.stringify(body) });
  // The API token must say who it runs as.
  let res = await call(bearer, { repo: INFRA, pr: 7, command: 'plan -p envs/dev' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /"as": "<login>"/);
  res = await call(bearer, { repo: INFRA, pr: 7, command: 'teriac apply -p envs/dev', as: 'alice' });
  assert.equal(res.status, 202);
  assert.deepEqual(handled.at(-1), { kind: 'api_command', repo: { platform: 'github', host: 'github.com', owner: 'acme', name: 'infra', fullName: 'acme/infra', cloneUrl: '' }, prNumber: 7, user: 'alice', text: 'teriac apply -p envs/dev', via: 'API token' });
  assert.equal((await call(bearer, { repo: INFRA, pr: 7, command: 'state rm -p envs/dev aws_s3_bucket.a', as: 'alice' })).status, 400, 'state commands: comment them');
  assert.equal((await call(bearer, { repo: INFRA, pr: 7, command: 'deploy', as: 'alice' })).status, 400);
  assert.equal((await call(bearer, { repo: INFRA, pr: 7, command: 'plan', as: 'not a login!' })).status, 400);
  // Signed in with GitHub: always as yourself, never "as" someone else; only your repos.
  const bob = (await signIn('bob')).cookie;
  const h = { Cookie: bob, 'X-Requested-With': 'teriac', 'Content-Type': 'application/json' };
  assert.equal((await call(h, { repo: INFRA, pr: 7, command: 'plan', as: 'ada' })).status, 202);
  assert.equal(handled.at(-1).user, 'bob');
  assert.equal(handled.at(-1).via, 'dashboard');
  assert.equal((await call(h, { repo: SECRET, pr: 1, command: 'plan' })).status, 404);
  // Password users have no GitHub identity.
  const pw = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'teriac' }, body: JSON.stringify({ username: 'vic', password: 'pw-vic-123' }) });
  const vic = { Cookie: cookieOf(pw, 'teriac_session'), 'X-Requested-With': 'teriac', 'Content-Type': 'application/json' };
  res = await call(vic, { repo: INFRA, pr: 7, command: 'plan', as: 'ada' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /need a GitHub identity/);
});
