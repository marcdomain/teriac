// HTTP endpoints: webhooks, health, metrics and a small read-only API.
import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { VcsAdapter, Platform } from './vcs/types.ts';
import type { App } from './app.ts';
import type { Store, Lock } from './store.ts';
import { platformForHost } from './links.ts';
import type { DriftScheduler } from './drift.ts';
import type { Person } from './config.ts';
import { presenter } from './present.ts';
import { isGrantor, parseGrantRequest, announce, grantText, type NotifyDeps } from './grants.ts';
import { windowUntil } from './freeze.ts';
import { matchGlob } from './glob.ts';
import { parseCommand } from './commands.ts';
import { destination, type BackupScheduler } from './backup.ts';
import type { ServerConfig } from './config.ts';
import { Avatars, roundAvatarSvg } from './avatars.ts';
import {
  type AuthConfig, type Oidc, type Role, type Session, checkLogin, newSession, parseCookies, unsign,
  RateLimiter, cookie, SESSION_COOKIE, OIDC_COOKIE, GITHUB_COOKIE, type GitHubLogin, type GitHubUserToken,
} from './auth.ts';
import { metrics } from './metrics.ts';
import { log } from './log.ts';

const MAX_BODY = 25 * 1024 * 1024; // GitHub's webhook limit

// The dashboard: a few static files, loaded once.
const WEB_DIR = join(import.meta.dirname, '..', 'web');
const WEB: Record<string, { type: string; body: string }> = {};
for (const [path, file, type] of [
  ['/', 'index.html', 'text/html; charset=utf-8'],
  ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
  ['/app.css', 'app.css', 'text/css; charset=utf-8'],
  ['/theme.js', 'theme.js', 'text/javascript; charset=utf-8'],
  ['/favicon.svg', 'logo.svg', 'image/svg+xml'],
] as const) {
  try { WEB[path] = { type, body: readFileSync(join(WEB_DIR, file), 'utf-8') }; } catch { /* dashboard not shipped */ }
}
// Fonts (Geist, SIL Open Font License; web/fonts/LICENSE-Geist.txt), served from here.
const FONTS: Record<string, Buffer> = {};
for (const f of ['geist-latin-wght-normal.woff2', 'geist-mono-latin-wght-normal.woff2']) {
  try { FONTS[`/fonts/${f}`] = readFileSync(join(WEB_DIR, 'fonts', f)); } catch { /* not shipped */ }
}
// The spinner GitHub shows in teriac's "Running…" replies (fetched by GitHub, so no auth).
let SPINNER: Buffer | null = null;
try { SPINNER = readFileSync(join(WEB_DIR, 'spinner.gif')); } catch { /* not shipped */ }

// The server's version (packages/server/package.json), shown in the dashboard.
let VERSION = 'dev';
try { VERSION = JSON.parse(readFileSync(join(WEB_DIR, '..', 'package.json'), 'utf-8')).version ?? 'dev'; } catch { /* not shipped */ }
const STARTED_AT = new Date().toISOString();
const statsCache = new Map<string, { at: number; data: ReturnType<Store['stats']> }>();


const WEB_HEADERS = {
  // Everything comes from this server; nothing inline, nothing third-party.
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-cache',
};

const readBody = (req: IncomingMessage): Promise<Buffer> => new Promise((resolve, reject) => {
  const chunks: Buffer[] = [];
  let size = 0;
  req.on('data', (c: Buffer) => {
    size += c.length;
    if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
    chunks.push(c);
  });
  req.on('end', () => resolve(Buffer.concat(chunks)));
  req.on('error', reject);
});

const send = (res: ServerResponse, status: number, body: unknown, type = 'application/json') => {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(type === 'application/json' ? JSON.stringify(body) : String(body));
};

const tokenOk = (req: IncomingMessage, token: string | undefined) => {
  if (!token) return false;
  const got = Buffer.from(String(req.headers.authorization ?? ''));
  const want = Buffer.from(`Bearer ${token}`);
  return got.length === want.length && timingSafeEqual(got, want);
};

export interface HttpDeps {
  app: App;
  store: Store;
  adapters: Partial<Record<Platform, VcsAdapter>>;
  auth: AuthConfig;
  oidc?: Oidc;
  github?: GitHubLogin;                       // Sign in with GitHub (the App's client ID and secret)
  ready: () => boolean;
  drift?: DriftScheduler;
  loginLimiter?: RateLimiter;
  platforms?: Record<string, Platform>;       // host → platform, for links
  people?: Person[];
  avatars?: Avatars;
  grants?: NotifyDeps;                        // emergency access (break_glass in repos.yaml)
  config?: ServerConfig;                      // for the Guardrails page (settings only, no secrets)
  backups?: BackupScheduler;                  // scheduled database backups (TERIAC_BACKUP_*)
}

// The guardrails in force, for the dashboard: freezes (on now or not), protected resources,
// risk and policy settings, the secret scan, and each repo entry's approval settings.
const safetySummary = (c: ServerConfig | undefined, now = new Date()) => {
  if (!c) return null;
  const freeze = (w: NonNullable<ServerConfig['freezes']>[number], scope: string) => ({
    scope, name: w.name, projects: w.projects ?? [], schedule: w.schedule ?? null, hours: w.hours ?? null,
    from: w.from ?? null, to: w.to ?? null, timezone: w.timezone ?? 'UTC', override: w.override ?? [], until: windowUntil(w, now),
  });
  const prot = (r: NonNullable<ServerConfig['protected']>[number], scope: string) => ({ scope, projects: r.projects ?? [], resources: r.resources, override: r.override ?? [] });
  return {
    freezes: [...(c.freezes ?? []).map(w => freeze(w, 'every repo')), ...c.repos.flatMap(r => (r.freezes ?? []).map(w => freeze(w, r.id)))],
    protected: [...(c.protected ?? []).map(r => prot(r, 'every repo')), ...c.repos.flatMap(r => (r.protected ?? []).map(x => prot(x, r.id)))],
    secretScan: { mode: c.secretScan?.mode ?? 'redact', patterns: (c.secretScan?.patterns ?? []).map(p => p.name) },
    policies: { mode: c.policies?.mode ?? 'off', builtin: c.policies?.builtin ?? [], disable: c.policies?.disable ?? [], rules: (c.policies?.rules ?? []).length, override: c.policies?.override ?? [] },
    risk: c.risk ?? null,
    breakGlass: c.breakGlass ? { grantors: c.breakGlass.grantors, maxHours: c.breakGlass.max_hours ?? 4 } : null,
    summary: c.summary ? { schedule: c.summary.schedule, timezone: c.summary.timezone ?? 'UTC', notify: c.summary.notify } : null,
    repos: c.repos.map(r => ({
      id: r.id, reapproveOnChange: r.reapprove_on_change ?? true, keepApprovalOnRebase: r.keep_approval_on_rebase ?? false,
      staleBase: r.stale_base ?? 'warn', verifyPlan: r.verify_plan ?? true, secretScan: r.secret_scan ?? null,
    })),
  };
};

const defaultLimiter = new RateLimiter(10, 15 * 60_000);

// Who is calling: an API token (automation, admin) or a dashboard session cookie. A session
// from a sign-in method that has since been turned off no longer counts. GitHub sessions
// take their role and repos from the latest check with GitHub (see `access` below).
type Who = Session & { cookie: boolean; repos?: string[] };
const whoIs = (req: IncomingMessage, auth: AuthConfig, store?: Store): Who | null => {
  if (req.headers.authorization) {
    return tokenOk(req, auth.apiToken)
      ? { sub: 'api-token', name: 'api-token', role: 'admin', via: 'token', exp: Infinity, cookie: false }
      : null;
  }
  const s = unsign<Session>(parseCookies(req.headers.cookie)[SESSION_COOKIE], auth.sessionSecret);
  if (!s) return null;
  if (s.via === 'password' && auth.passwordLogin === false) return null;
  if (s.via === 'oidc' && !auth.oidc) return null;
  if (s.via === 'github') {
    const a = auth.github ? store?.getAccess(s.sub) : null;
    if (!a || a.role === 'none') return null;
    return { ...s, role: a.role, repos: a.role === 'admin' ? undefined : a.repos, cookie: true };
  }
  return { ...s, cookie: true };
};

const ROLE_RANK: Record<Role, number> = { viewer: 1, admin: 2 };

const redirect = (res: ServerResponse, location: string, setCookie?: string[]) => {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store', ...(setCookie ? { 'Set-Cookie': setCookie } : {}) });
  res.end();
};

// GitHub sessions are checked with GitHub again every few minutes (while the server has the
// person's token): repos they lost access to disappear, and someone removed from the org or
// an admin team loses access or admin. After a restart (no token) the last check stands
// until the session ends; GitHub sessions last at most 8 hours.
const RECHECK_MS = 10 * 60_000;
const GITHUB_SESSION_HOURS = 8;

export const createHttpServer = (deps: HttpDeps): Server => {
  const show = presenter(deps.platforms ?? {}, deps.people ?? []);
  const ghTokens = new Map<string, GitHubUserToken>();
  const rechecking = new Set<string>();
  const recheck = (who: Who) => {
    const gh = deps.github;
    const token = ghTokens.get(who.sub);
    const a = deps.store.getAccess(who.sub);
    if (!gh || !token || !a || rechecking.has(who.sub) || Date.now() - Date.parse(a.at) < RECHECK_MS) return;
    rechecking.add(who.sub);
    void (async () => {
      let t = token;
      if (t.expires - 60_000 < Date.now()) { t = await gh.refresh(t); ghTokens.set(who.sub, t); }
      const repos = await gh.repos(t.access);
      const role = await gh.role(who.login ?? who.name, repos);
      deps.store.setAccess(who.sub, repos, role ?? 'none');
      if (!role) { ghTokens.delete(who.sub); log.info('dashboard access ended', { user: who.sub }); }
    })().catch(err => {
      if ((err as { revoked?: boolean }).revoked || /refresh/.test((err as Error).message)) {
        deps.store.setAccess(who.sub, [], 'none');
        ghTokens.delete(who.sub);
        log.info('dashboard access ended: GitHub no longer accepts the sign-in', { user: who.sub });
      } else log.warn('checking GitHub access failed; keeping the last check', { user: who.sub, err: (err as Error).message });
    }).finally(() => rechecking.delete(who.sub));
  };
  // Releasing a lock from the dashboard: admins; or, signed in with GitHub, the person who
  // holds it, or anyone the repo's `unlock` permission allows (default maintain).
  const canUnlock = async (who: Who, lock: Lock): Promise<boolean> => {
    if (ROLE_RANK[who.role] >= ROLE_RANK.admin) return true;
    if (who.via !== 'github' || !who.login || !(who.repos ?? []).includes(lock.repo)) return false;
    if (lock.user.toLowerCase() === who.login.toLowerCase()) return true;
    const adapter = deps.adapters[platformForHost(lock.repo.split('/')[0], deps.platforms ?? {})];
    if (!adapter || !deps.app.mayUnlock) return false;
    return (await deps.app.mayUnlock(adapter, lock, who.login).catch(() => ({ allowed: false }))).allowed;
  };
  return createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (req.method === 'GET' && url.pathname === '/readyz') {
      return deps.ready() ? send(res, 200, { ok: true }) : send(res, 503, { ok: false });
    }
    if (req.method === 'GET' && url.pathname === '/assets/spinner.gif' && SPINNER) {
      res.writeHead(200, { 'Content-Type': 'image/gif', 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
      return res.end(SPINNER);
    }
    if (req.method === 'GET' && url.pathname === '/metrics') {
      const extra: Record<string, number> = { teriac_locks: deps.store.allLocks().length };
      if (deps.backups) {
        const recent = deps.store.recentBackups(50);
        const ok = recent.find(b => b.ok);
        extra.teriac_backup_last_ok = recent[0] ? (recent[0].ok ? 1 : 0) : 1;
        extra.teriac_backup_last_success_timestamp_seconds = ok ? Math.floor(Date.parse(ok.at) / 1000) : 0;
        if (ok?.bytes) extra.teriac_backup_last_size_bytes = ok.bytes;
      }
      return send(res, 200, metrics.render(extra), 'text/plain; version=0.0.4');
    }

    const hook = /^\/events\/([a-z]+)$/.exec(url.pathname);
    if (req.method === 'POST' && hook) {
      const adapter = deps.adapters[hook[1] as Platform];
      if (!adapter) return send(res, 404, { error: 'platform not configured' });
      const raw = await readBody(req);
      if (!adapter.verify(req.headers, raw)) {
        log.warn('webhook signature rejected', { platform: hook[1] });
        return send(res, 401, { error: 'bad signature' });
      }
      const event = adapter.parse(req.headers, JSON.parse(raw.toString('utf-8')));
      metrics.webhook(adapter.platform, event.kind);
      // Answer now; platforms time out webhooks after ~10s and plans take longer.
      send(res, 202, { accepted: event.kind });
      deps.app.handle(adapter, event).catch(err => log.error('event handling failed', { err }));
      return;
    }

    // ---- sign-in -----------------------------------------------------------
    const { auth } = deps;
    if (req.method === 'GET' && url.pathname === '/auth/config') {
      return send(res, 200, {
        password: auth.passwordLogin !== false && auth.users.length > 0,
        oidc: auth.oidc ? { name: auth.oidc.name } : null,
        github: !!deps.github,
        token: !!auth.apiToken,
      });
    }
    if (req.method === 'POST' && url.pathname === '/auth/login') {
      if (req.headers['x-requested-with'] !== 'teriac') return send(res, 403, { error: 'missing X-Requested-With header' });
      if (auth.passwordLogin === false) return send(res, 404, { error: 'Password sign-in is turned off on this server.' });
      const body = JSON.parse((await readBody(req)).toString('utf-8') || '{}');
      const username = String(body.username ?? '');
      const ip = String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').split(',')[0].trim();
      const loginLimiter = deps.loginLimiter ?? defaultLimiter;
      if (!loginLimiter.allow(`ip:${ip}`) || !loginLimiter.allow(`user:${username}`)) {
        return send(res, 429, { error: 'Too many sign-in attempts. Wait 15 minutes and try again.' });
      }
      const user = checkLogin(auth.users, username, String(body.password ?? ''));
      if (!user) {
        log.warn('dashboard sign-in failed', { username, ip });
        return send(res, 401, { error: 'Wrong username or password.' });
      }
      loginLimiter.reset(`user:${username}`);
      const { session, setCookie } = newSession(auth, { sub: user.username, name: user.name ?? user.username, role: user.role ?? 'viewer', via: 'password' });
      res.setHeader('Set-Cookie', setCookie);
      log.info('dashboard sign-in', { user: session.sub, via: 'password', role: session.role });
      return send(res, 200, { name: session.name, role: session.role });
    }
    if (req.method === 'GET' && url.pathname === '/auth/oidc/login') {
      if (!deps.oidc) return send(res, 404, { error: 'single sign-on is not configured' });
      const { url: to, setCookie } = await deps.oidc.start(auth.sessionSecret, auth);
      return redirect(res, to, [setCookie]);
    }
    if (req.method === 'GET' && url.pathname === '/auth/oidc/callback') {
      if (!deps.oidc) return send(res, 404, { error: 'single sign-on is not configured' });
      const clearState = cookie(OIDC_COOKIE, '', auth, 0);
      try {
        const who = await deps.oidc.finish(url.searchParams, parseCookies(req.headers.cookie)[OIDC_COOKIE], auth.sessionSecret);
        const { session, setCookie } = newSession(auth, who);
        log.info('dashboard sign-in', { user: session.sub, via: 'oidc', role: session.role });
        return redirect(res, '/#overview', [setCookie, clearState]);
      } catch (err) {
        log.warn('single sign-on failed', { err });
        return redirect(res, `/#signin-error=${encodeURIComponent((err as Error).message)}`, [clearState]);
      }
    }
    if (req.method === 'GET' && url.pathname === '/auth/github/login') {
      if (!deps.github) return send(res, 404, { error: 'GitHub sign-in is not configured' });
      const { url: to, setCookie } = deps.github.start(auth.sessionSecret, auth);
      return redirect(res, to, [setCookie]);
    }
    if (req.method === 'GET' && url.pathname === '/auth/github/callback') {
      if (!deps.github) return send(res, 404, { error: 'GitHub sign-in is not configured' });
      const clearState = cookie(GITHUB_COOKIE, '', auth, 0);
      try {
        const r = await deps.github.finish(url.searchParams, parseCookies(req.headers.cookie)[GITHUB_COOKIE], auth.sessionSecret);
        deps.store.setAccess(r.session.sub, r.repos, r.session.role);
        ghTokens.set(r.session.sub, r.token);
        const { session, setCookie } = newSession({ ...auth, sessionHours: Math.min(auth.sessionHours, GITHUB_SESSION_HOURS) }, r.session);
        log.info('dashboard sign-in', { user: session.sub, via: 'github', role: session.role, repos: r.repos.length });
        return redirect(res, '/#overview', [setCookie, clearState]);
      } catch (err) {
        log.warn('GitHub sign-in failed', { err });
        return redirect(res, `/#signin-error=${encodeURIComponent((err as Error).message)}`, [clearState]);
      }
    }
    if (req.method === 'POST' && url.pathname === '/auth/logout') {
      const s = unsign<Session>(parseCookies(req.headers.cookie)[SESSION_COOKIE], auth.sessionSecret);
      if (s?.via === 'github') ghTokens.delete(s.sub);
      res.setHeader('Set-Cookie', cookie(SESSION_COOKIE, '', auth, 0));
      return send(res, 200, { ok: true });
    }

    // Round avatars for PR comments: public (GitHub's image proxy fetches them), known hosts only.
    const round = /^\/avatars\/round\/([^/]+)\/([^/]+)\.svg$/.exec(url.pathname);
    if (req.method === 'GET' && round && deps.avatars) {
      const host = decodeURIComponent(round[1]);
      const login = decodeURIComponent(round[2]);
      if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(login) || !deps.avatars.knows(host)) return send(res, 404, { error: 'not found' });
      const img = await deps.avatars.get(host, login);
      res.writeHead(200, { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; img-src data:; style-src 'unsafe-inline'" });
      return res.end(roundAvatarSvg(login, img));
    }

    // Avatars, served from here (signed-in users only; known hosts only).
    const av = /^\/avatars\/([^/]+)\/([^/]+)$/.exec(url.pathname);
    if (req.method === 'GET' && av) {
      if (!whoIs(req, auth, deps.store) || !deps.avatars) return send(res, 404, { error: 'not found' });
      const img = await deps.avatars.get(decodeURIComponent(av[1]), decodeURIComponent(av[2]));
      if (!img) return send(res, 404, { error: 'no avatar' });
      res.writeHead(200, { 'Content-Type': img.type, 'Cache-Control': 'private, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
      return res.end(img.body);
    }

    // ---- API: viewers read, admins act ----------------------------------------
    if (url.pathname.startsWith('/api/')) {
      const who = whoIs(req, auth, deps.store);
      if (!who) return send(res, 401, { error: 'sign in first' });
      if (who.via === 'github') recheck(who);
      // GitHub viewers see only the repos they can see on GitHub; everyone else sees all.
      const scope = who.repos;
      const inScope = (repo: string) => !scope || scope.includes(repo);
      const isWrite = req.method !== 'GET';
      // Browsers can't add this header to a cross-site request without CORS approval.
      if (isWrite && who.cookie && req.headers['x-requested-with'] !== 'teriac') return send(res, 403, { error: 'missing X-Requested-With header' });
      const need = (role: Role) => ROLE_RANK[who.role] >= ROLE_RANK[role];

      if (req.method === 'GET' && url.pathname === '/api/me') {
        const names: Record<string, string> = { github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket', azure: 'Azure DevOps' };
        const platforms = [...new Set(Object.values(deps.platforms ?? {}))].map(p => ({ id: p, name: names[p] ?? p }));
        return send(res, 200, { name: who.name, role: who.role, via: who.via, login: who.login ?? null, repos: scope ? scope.length : null, platforms, version: VERSION });
      }

      if (req.method === 'GET' && url.pathname === '/api/stats') {
        // Either the last N days, or a custom from/to (dates or ISO times; "to" is exclusive).
        const date = (k: string) => { const v = url.searchParams.get(k); const t = v ? Date.parse(v) : NaN; return Number.isNaN(t) ? null : t; };
        let fromMs = date('from');
        let toMs = date('to');
        if (fromMs === null) {
          const n = Math.min(365, Math.max(1, Number(url.searchParams.get('days')) || 30));
          fromMs = Date.now() - n * 864e5;
          toMs = null;
        }
        if (toMs !== null && toMs <= fromMs) return send(res, 400, { error: '"to" must be after "from"' });
        if ((toMs ?? Date.now()) - fromMs > 3 * 366 * 864e5) return send(res, 400, { error: 'the range can be at most 3 years' });
        const from = new Date(fromMs).toISOString();
        const to = toMs === null ? undefined : new Date(toMs).toISOString();
        const days = Math.max(1, Math.ceil(((toMs ?? Date.now()) - fromMs) / 864e5));
        // Cached for 30 seconds: dashboards refresh often, and the numbers barely move.
        const cacheKey = `${scope ? who.sub : '*'}|${url.searchParams.get('days') ?? ''}|${from.slice(0, 16)}|${to ?? ''}`;
        const hit = statsCache.get(cacheKey);
        let stats = hit && Date.now() - hit.at < 30_000 ? hit.data : null;
        if (!stats) {
          stats = deps.store.stats(from, to, scope);
          statsCache.set(cacheKey, { at: Date.now(), data: stats });
          if (statsCache.size > 50) statsCache.delete(statsCache.keys().next().value!);
        }
        return send(res, 200, {
          days, to: to ?? null, ...stats,
          server: {
            version: VERSION, node: process.version, uptime: Math.round(process.uptime()),
            memory: process.memoryUsage().rss, queue: deps.app.runQueue ?? null, startedAt: STARTED_AT,
          },
        });
      }

      if (req.method === 'POST' && url.pathname === '/api/locks/unlock') {
        const body = JSON.parse((await readBody(req)).toString('utf-8') || '{}');
        const lock = deps.store.getLock(String(body.repo), String(body.project), String(body.workspace ?? 'default'));
        if (!lock || !inScope(lock.repo)) return send(res, 404, { error: 'no such lock' });
        if (!(await canUnlock(who, lock))) return send(res, 403, { error: 'You can release your own locks, and others where the repo\'s unlock permission allows you (default: maintain or admin on GitHub). Ask an admin for others.' });
        deps.store.releaseLock(lock.repo, lock.project, lock.workspace);
        deps.store.audit({ repo: lock.repo, pr: lock.pr, user: who.name, action: 'unlock', project: lock.project, allowed: true, reason: `released from the dashboard (${who.via})` });
        const host = lock.repo.split('/')[0];
        const adapter = deps.adapters[platformForHost(host, deps.platforms ?? {})];
        const notified = await deps.app.dashboardUnlock(adapter, lock, who);
        return send(res, 200, { released: lock, notified });
      }

      // ---- emergency access ----
      if (url.pathname === '/api/grants' && req.method === 'GET') {
        const g = deps.grants;
        return send(res, 200, {
          enabled: !!g?.cfg,
          canGrant: isGrantor(who, g?.cfg),
          maxHours: g?.cfg?.max_hours ?? 4,
          active: deps.store.activeGrants().filter(x => inScope(x.repo)),
          recent: deps.store.listGrants(50).filter(x => inScope(x.repo)),
        });
      }
      if (url.pathname === '/api/grants' && req.method === 'POST') {
        const g = deps.grants;
        if (!g?.cfg) return send(res, 404, { error: 'Emergency access is not set up (break_glass in repos.yaml).' });
        if (!isGrantor(who, g.cfg)) return send(res, 403, { error: 'You are not allowed to grant emergency access.' });
        const parsed = parseGrantRequest(JSON.parse((await readBody(req)).toString('utf-8') || '{}'), g.cfg);
        if ('error' in parsed) return send(res, 400, parsed);
        const grant = deps.store.createGrant({ ...parsed, grantedBy: `${who.name} (${who.via})`, expiresAt: new Date(Date.now() + parsed.hours * 3_600_000).toISOString() });
        deps.store.audit({ repo: grant.repo, pr: 0, user: grant.user, action: 'break_glass_granted', project: grant.projects.join(',') || '*', allowed: true, reason: `emergency access #${grant.id} by ${grant.grantedBy} for ${parsed.hours}h: ${grantText(grant)}. Reason: ${grant.reason}` });
        log.warn('emergency access granted', { id: grant.id, user: grant.user, by: grant.grantedBy, hours: parsed.hours });
        void announce(g, `🚨 Emergency access #${grant.id} granted to ${grant.user}`, grant, 'teriac.break_glass.granted').catch(() => {});
        return send(res, 201, grant);
      }
      const revoke = /^\/api\/grants\/(\d+)\/revoke$/.exec(url.pathname);
      if (revoke && req.method === 'POST') {
        const g = deps.grants;
        if (!need('admin') && !isGrantor(who, g?.cfg)) return send(res, 403, { error: 'Only admins and grantors can revoke emergency access.' });
        const grant = deps.store.getGrant(Number(revoke[1]));
        if (!grant) return send(res, 404, { error: 'no such grant' });
        if (!deps.store.revokeGrant(grant.id, who.name)) return send(res, 409, { error: 'already revoked' });
        deps.store.audit({ repo: grant.repo, pr: 0, user: grant.user, action: 'break_glass_revoked', project: grant.projects.join(',') || '*', allowed: true, reason: `emergency access #${grant.id} revoked by ${who.name}` });
        if (g) void announce(g, `🔒 Emergency access #${grant.id} for ${grant.user} revoked by ${who.name}`, grant, 'teriac.break_glass.revoked').catch(() => {});
        return send(res, 200, deps.store.getGrant(grant.id));
      }

      // ---- backups ----
      if (url.pathname === '/api/backups' && req.method === 'GET') {
        const c = deps.config?.backup;
        if (!c || !deps.backups) return send(res, 200, { enabled: false });
        return send(res, 200, {
          enabled: true, schedule: c.schedule, timezone: c.timezone, destination: destination(c),
          next: deps.backups.next(), running: deps.backups.busy, canRun: need('admin'),
          runs: deps.store.recentBackups(Math.min(100, Number(url.searchParams.get('limit') ?? 10))),
        });
      }
      if (url.pathname === '/api/backups/run' && req.method === 'POST') {
        if (!deps.backups) return send(res, 404, { error: 'Backups are off. Set backup.enabled (TERIAC_BACKUP_ENABLED) to turn them on.' });
        if (!need('admin')) return send(res, 403, { error: 'Only admins can start a backup.' });
        const run = await deps.backups.run('manual');
        deps.store.audit({ repo: '*', pr: 0, user: who.name, action: 'backup', project: '*', allowed: run.ok, reason: run.ok ? `backup ${run.name} from the dashboard (${who.via})` : `backup from the dashboard failed: ${run.error}` });
        return send(res, run.ok ? 200 : 502, run);
      }

      // ---- pause all applies (an emergency stop; freezes in repos.yaml are for planned ones) ----
      if (url.pathname === '/api/applies' && req.method === 'GET') {
        return send(res, 200, { paused: deps.app.appliesPaused?.() ?? null, canChange: need('admin') });
      }
      if (url.pathname === '/api/applies/pause' && req.method === 'POST') {
        if (!need('admin')) return send(res, 403, { error: 'Only admins can pause applies.' });
        const body = JSON.parse((await readBody(req)).toString('utf-8') || '{}');
        const reason = String(body.reason ?? '').trim().slice(0, 200);
        if (!reason) return send(res, 400, { error: 'Say why applies are paused (it is shown on every blocked apply).' });
        const p = { by: who.name, via: who.via, at: new Date().toISOString(), reason };
        deps.app.pauseApplies(p);
        deps.store.audit({ repo: '*', pr: 0, user: who.name, action: 'applies_paused', project: '*', allowed: true, reason });
        return send(res, 200, { paused: p });
      }
      if (url.pathname === '/api/applies/resume' && req.method === 'POST') {
        if (!need('admin')) return send(res, 403, { error: 'Only admins can resume applies.' });
        const was = deps.app.appliesPaused();
        deps.app.resumeApplies();
        deps.store.audit({ repo: '*', pr: 0, user: who.name, action: 'applies_resumed', project: '*', allowed: true, reason: was ? `paused by ${was.by}: ${was.reason}` : 'was not paused' });
        return send(res, 200, { paused: null });
      }

      // Run a PR command from outside GitHub: plan, apply, unlock or cancel. It runs as a GitHub
      // login, so that person's permissions and the PR's approvals apply as for a comment;
      // the result is posted on the PR. Signed in with GitHub: yourself. API token: `as`.
      if (req.method === 'POST' && url.pathname === '/api/commands') {
        const body = JSON.parse((await readBody(req)).toString('utf-8') || '{}');
        const repoKey = String(body.repo ?? '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
        const pr = Number(body.pr);
        const text = String(body.command ?? '').trim().replace(/^teriac\s+/, '');
        const as = who.via === 'github' ? who.login : who.via === 'token' ? String(body.as ?? '').trim() : '';
        if (!as) return send(res, 400, { error: who.via === 'token' ? 'Say which GitHub login this runs as: "as": "<login>". Their permissions apply.' : 'Commands need a GitHub identity: sign in with GitHub, or use the API token with "as".' });
        if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(as)) return send(res, 400, { error: '"as" must be a GitHub login' });
        if (!/^[^/]+\/[^/]+\/[^/]+$/.test(repoKey) || !Number.isInteger(pr) || pr < 1) return send(res, 400, { error: 'Give "repo" as host/owner/name (e.g. github.com/acme/infra) and "pr" as a number.' });
        if (!inScope(repoKey)) return send(res, 404, { error: 'no such repo' });
        const full = `${deps.app.commandName ?? 'teriac'} ${text}`;
        const parsed = parseCommand(full, [deps.app.commandName ?? 'teriac']);
        if (!parsed) return send(res, 400, { error: 'Give a command, e.g. "plan -p envs/dev".' });
        if (!parsed.ok) return send(res, 400, { error: parsed.error });
        if (!['plan', 'apply', 'unlock', 'cancel'].includes(parsed.command.verb)) return send(res, 400, { error: 'The API runs plan, apply, unlock and cancel. Comment other commands on the PR.' });
        const [host, owner, name] = repoKey.split('/');
        const adapter = deps.adapters[platformForHost(host, deps.platforms ?? {})];
        if (!adapter) return send(res, 404, { error: 'no such repo' });
        const repo = { platform: adapter.platform, host, owner, name, fullName: `${owner}/${name}`, cloneUrl: '' };
        log.info('API command', { repo: repoKey, pr, command: full, as, by: who.sub });
        send(res, 202, { accepted: full, pr, as, note: 'teriac checks permissions and posts the result on the pull request.' });
        deps.app.handle(adapter, { kind: 'api_command', repo, prNumber: pr, user: as, text: full, via: who.via === 'token' ? 'API token' : 'dashboard' }).catch(err => log.error('API command failed', { err }));
        return;
      }

      if (req.method === 'POST' && url.pathname === '/api/drift/run') {
        if (!need('admin')) return send(res, 403, { error: 'Only admins can start drift checks.' });
        const entry = deps.drift?.schedules.find(e => e.key === url.searchParams.get('key'));
        if (!entry) return send(res, 404, { error: 'no schedule with that key; see GET /api/drift/schedules' });
        send(res, 202, { started: entry.key });
        deps.drift!.run(entry).catch(err => log.error('manual drift run failed', { err }));
        return;
      }

      // Live output of a running plan or apply (server-sent events): the lines so far, then
      // each new batch, then "done". Lines are cleaned of secrets before they get here.
      const liveRun = /^\/api\/runs\/(\d+)\/live$/.exec(url.pathname);
      if (req.method === 'GET' && liveRun) {
        const id = Number(liveRun[1]);
        const run = deps.store.getRun(id);
        if (!run || !inScope(run.repo)) return send(res, 404, { error: 'no such run' });
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff' });
        const event = (name: string, data: unknown) => res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);
        let ping: NodeJS.Timeout | undefined;
        let closed = false;
        req.on('close', () => { closed = true; });
        // A run that's still starting may not have live output yet: wait a little for it.
        if (!deps.app.live?.has(id) && (run.status === 'running' || run.status === 'queued')) {
          for (let i = 0; i < 40 && !deps.app.live?.has(id) && !closed; i++) await new Promise(r => setTimeout(r, 250));
        }
        const finish = () => { clearInterval(ping); if (!res.writableEnded) { event('done', {}); res.end(); } };
        const sub = deps.app.live?.subscribe(id, (lines, done) => {
          if (lines.length && !res.writableEnded) event('lines', lines);
          if (done) finish();
        });
        if (!sub) { event('done', { saved: true }); return res.end(); }
        if (sub.dropped) event('dropped', sub.dropped);
        if (sub.backlog.length) event('lines', sub.backlog);
        if (sub.done) return finish();
        ping = setInterval(() => res.write(': ping\n\n'), 15_000);
        req.on('close', () => { clearInterval(ping); sub.stop(); });
        return;
      }

      if (req.method === 'GET') {
        if (url.pathname === '/api/locks') {
          const locks = deps.store.allLocks().filter(l => inScope(l.repo));
          return send(res, 200, await Promise.all(locks.map(async l => ({ ...show.lock(l), canUnlock: await canUnlock(who, l) }))));
        }
        if (url.pathname === '/api/runs') {
          return send(res, 200, deps.store.recentRuns(Math.min(200, Number(url.searchParams.get('limit') ?? 50)), scope).map(r => ({ ...show.run(r), output: undefined })));
        }
        const run = /^\/api\/runs\/(\d+)$/.exec(url.pathname);
        if (run) {
          const r = deps.store.getRun(Number(run[1]));
          return r && inScope(r.repo) ? send(res, 200, show.run(r)) : send(res, 404, { error: 'not found' });
        }
        if (url.pathname === '/api/audit') return send(res, 200, deps.store.auditLog(200, scope).map(show.audit));
        const qp = url.searchParams;
        const str = (k: string) => (qp.get(k) ?? '').trim() || undefined;
        const num = (k: string) => (qp.get(k) ? Number(qp.get(k)) : undefined);
        const oneOf = <T extends string>(k: string, allowed: readonly T[]) => {
          const v = str(k);
          return v && (allowed as readonly string[]).includes(v) ? (v as T) : undefined;
        };
        const time = (k: string) => {
          const v = str(k);
          return v && !Number.isNaN(Date.parse(v)) ? new Date(v).toISOString() : undefined;
        };
        if (url.pathname === '/api/runs/search') {
          const r = deps.store.searchRuns({
            q: str('q'), user: str('user'), project: str('project'), repo: str('repo'),
            status: oneOf('status', ['failed', 'applied', 'destroys', 'changes', 'nochanges', 'running'] as const),
            kind: oneOf('kind', ['plan', 'apply'] as const),
            from: time('from'), to: time('to'),
            sort: oneOf('sort', ['newest', 'oldest', 'project', 'user', 'changes'] as const),
            limit: num('limit'), offset: num('offset'), repos: scope,
          });
          return send(res, 200, { total: r.total, items: r.items.map(show.run) });
        }
        if (url.pathname === '/api/audit/search') {
          const allowed = str('result');
          const r = deps.store.searchAudit({
            q: str('q'), user: str('user'), project: str('project'), action: str('action'),
            allowed: allowed === 'allowed' ? true : allowed === 'denied' ? false : undefined,
            from: time('from'), to: time('to'), limit: num('limit'), offset: num('offset'), repos: scope,
          });
          return send(res, 200, { total: r.total, items: r.items.map(show.audit) });
        }
        if (url.pathname === '/api/facets') return send(res, 200, { ...deps.store.facets(scope), rules: deps.store.findingRules(scope) });
        if (url.pathname === '/api/policy/search') {
          const r = deps.store.searchFindings({
            q: str('q'), project: str('project'), rule: str('rule'),
            severity: oneOf('severity', ['low', 'medium', 'high', 'critical'] as const),
            mode: oneOf('mode', ['audit', 'enforce'] as const),
            from: time('from'), to: time('to'), limit: num('limit'), offset: num('offset'), repos: scope,
          });
          return send(res, 200, { total: r.total, items: r.items.map(show.finding) });
        }
        if (url.pathname === '/api/projects') {
          return send(res, 200, deps.store.projectSummaries(scope).map(p => ({
            ...p, lastRun: show.run(p.lastRun), lastApply: p.lastApply ? show.run(p.lastApply) : null, lock: p.lock ? show.lock(p.lock) : null,
          })));
        }
        if (url.pathname === '/api/ping') return send(res, 200, { ok: true });
        if (url.pathname === '/api/safety') {
          const s = safetySummary(deps.config);
          // A GitHub viewer sees the settings of their own repos only.
          if (s && scope) s.repos = s.repos.filter(r => scope.some(k => matchGlob(r.id, k)));
          return send(res, 200, s ?? { error: 'not available' });
        }
        if (url.pathname === '/api/drift') return send(res, 200, deps.store.recentDrift(200, scope).map(show.drift));
        if (url.pathname === '/api/drift/schedules') {
          return send(res, 200, (deps.drift?.schedules ?? []).filter(e => inScope(`${e.repo.host}/${e.repo.fullName}`)).map(e => ({
            key: e.key, source: e.source, repo: e.repo.fullName, branch: e.branch, name: e.spec.name ?? null,
            schedule: e.spec.schedule, timezone: e.spec.timezone ?? 'UTC', projects: e.spec.projects,
            notify: e.spec.notify, next: deps.drift!.next(e)?.toISOString() ?? null,
          })));
        }
      }
      return send(res, 404, { error: 'not found' });
    }

    const font = req.method === 'GET' ? FONTS[url.pathname] : undefined;
    if (font) {
      res.writeHead(200, { 'Content-Type': 'font/woff2', 'Cache-Control': 'public, max-age=604800, immutable', 'X-Content-Type-Options': 'nosniff' });
      return res.end(font);
    }
    const page = req.method === 'GET' ? WEB[url.pathname] : undefined;
    if (page) {
      res.writeHead(200, { 'Content-Type': page.type, ...WEB_HEADERS });
      return res.end(page.body);
    }
    send(res, 404, { error: 'not found' });
  } catch (err) {
    log.error('request failed', { path: url.pathname, err });
    if (!res.headersSent) send(res, 400, { error: 'bad request' });
  }
});
};
