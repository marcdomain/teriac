// Dashboard sign-in: username/password, OIDC (Okta, Azure AD, Google, Keycloak, ...),
// GitHub (the App's own sign-in) and API tokens. Sessions are HMAC-signed, HttpOnly cookies.
import { createHash, createHmac, createPublicKey, createVerify, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

export type Role = 'admin' | 'viewer';

export interface Session {
  sub: string;            // username or OIDC subject
  name: string;           // shown in the UI and the audit log
  role: Role;
  via: 'password' | 'oidc' | 'github' | 'token';
  login?: string;         // GitHub sign-in: the GitHub login (repo access and permissions come from GitHub)
  exp: number;            // epoch seconds
  email?: string;         // single sign-on only
  groups?: string[];      // single sign-on groups (for emergency-access grantors)
}

export interface DashboardUser {
  username: string;
  password_hash: string;  // from `node packages/server/src/hash-password.ts`
  role?: Role;            // default viewer
  name?: string;
}

export interface OidcConfig {
  issuer: string;         // e.g. https://acme.okta.com/oauth2/default
  clientId: string;
  clientSecret: string;
  name: string;           // button label, e.g. "Okta"
  scopes: string[];
  groupsClaim: string;    // claim holding the user's groups
  adminGroups: string[];  // members become admins
  allowedGroups: string[];// if set, only these groups may sign in
}

export interface GitHubLoginConfig {
  clientId: string;       // the GitHub App's client ID and secret
  clientSecret: string;
  webUrl: string;         // https://github.com, or the GitHub Enterprise Server address
  apiUrl: string;
  host: string;
  adminUsers: string[];   // TERIAC_GITHUB_ADMIN_USERS: these logins are dashboard admins
  adminTeams: string[];   // TERIAC_GITHUB_ADMIN_TEAMS: members of these teams ("org/slug") are admins
  allowedTeams: string[]; // TERIAC_GITHUB_ALLOWED_TEAMS: if set, only these teams (and admins) may sign in
}

export interface AuthConfig {
  apiToken?: string;
  sessionSecret: string;
  sessionHours: number;
  secureCookies: boolean;
  users: DashboardUser[];
  passwordLogin?: boolean; // TERIAC_DASHBOARD_PASSWORD_LOGIN (default true): username/password sign-in
  oidc?: OidcConfig;
  github?: GitHubLoginConfig;
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
const safeEqual = (a: string, b: string) => {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

// ---- passwords (scrypt) -----------------------------------------------------

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

export const hashPassword = (password: string): string => {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${hash.toString('base64')}`;
};

export const verifyPassword = (password: string, stored: string): boolean => {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, salt, hash] = parts;
  const expected = Buffer.from(hash, 'base64');
  const got = scryptSync(password, Buffer.from(salt, 'base64'), expected.length, { N: Number(N), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 });
  return got.length === expected.length && timingSafeEqual(got, expected);
};

// A real-looking hash to compare against when the username is unknown, so
// response time doesn't reveal which usernames exist.
const DUMMY_HASH = hashPassword(randomBytes(16).toString('hex'));

export const checkLogin = (users: DashboardUser[], username: string, password: string): DashboardUser | null => {
  const user = users.find(u => u.username === username);
  const ok = verifyPassword(password, user?.password_hash ?? DUMMY_HASH);
  return user && ok ? user : null;
};

// ---- signed values (sessions, OIDC state) -------------------------------------

export const sign = (payload: object, secret: string): string => {
  const body = b64url(JSON.stringify(payload));
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
};

export const unsign = <T extends { exp: number }>(value: string | undefined, secret: string): T | null => {
  if (!value) return null;
  const [body, mac] = value.split('.');
  if (!body || !mac || !safeEqual(mac, createHmac('sha256', secret).update(body).digest('base64url'))) return null;
  try {
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf-8')) as T;
    return typeof data.exp === 'number' && data.exp > now() ? data : null;
  } catch {
    return null;
  }
};

export const parseCookies = (header: string | undefined): Record<string, string> =>
  Object.fromEntries((header ?? '').split(';').map(c => c.trim()).filter(Boolean).map(c => {
    const i = c.indexOf('=');
    return [c.slice(0, i), decodeURIComponent(c.slice(i + 1))];
  }));

export const cookie = (name: string, value: string, cfg: AuthConfig, maxAgeSeconds: number) =>
  `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${cfg.secureCookies ? '; Secure' : ''}`;

export const SESSION_COOKIE = 'teriac_session';
export const OIDC_COOKIE = 'teriac_oidc';
export const GITHUB_COOKIE = 'teriac_github';

export const newSession = (cfg: AuthConfig, s: Omit<Session, 'exp'>): { session: Session; setCookie: string } => {
  const session = { ...s, exp: now() + cfg.sessionHours * 3600 };
  return { session, setCookie: cookie(SESSION_COOKIE, sign(session, cfg.sessionSecret), cfg, cfg.sessionHours * 3600) };
};

// ---- brute-force protection -------------------------------------------------------

export class RateLimiter {
  private hits = new Map<string, number[]>();
  private max: number;
  private windowMs: number;
  constructor(max = 10, windowMs = 15 * 60_000) { this.max = max; this.windowMs = windowMs; }
  // True when `key` is still under the limit (and counts this attempt).
  allow(key: string): boolean {
    const t = Date.now();
    const list = (this.hits.get(key) ?? []).filter(x => t - x < this.windowMs);
    list.push(t);
    this.hits.set(key, list);
    return list.length <= this.max;
  }
  reset(key: string) { this.hits.delete(key); }
}

// ---- OIDC (authorization code + PKCE) -------------------------------------------------

interface Discovery { authorization_endpoint: string; token_endpoint: string; jwks_uri: string; issuer: string }
interface Jwk { kid?: string; kty: string; alg?: string; use?: string; n?: string; e?: string }

export interface OidcState { state: string; nonce: string; verifier: string; exp: number }

export class Oidc {
  private cfg: OidcConfig;
  private redirectUri: string;
  private fetchImpl: typeof fetch;
  private discovery: Discovery | null = null;
  private jwks: Jwk[] = [];

  constructor(cfg: OidcConfig, publicUrl: string, fetchImpl: typeof fetch = fetch) {
    this.cfg = cfg;
    this.redirectUri = `${publicUrl}/auth/oidc/callback`;
    this.fetchImpl = fetchImpl;
  }

  private async getJson<T>(url: string, init?: RequestInit): Promise<T> {
    const res = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`OIDC: ${url} answered HTTP ${res.status}`);
    return res.json() as Promise<T>;
  }

  private async discover(): Promise<Discovery> {
    if (!this.discovery) {
      const d = await this.getJson<Discovery>(`${this.cfg.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`);
      if (d.issuer.replace(/\/+$/, '') !== this.cfg.issuer.replace(/\/+$/, '')) throw new Error('OIDC: issuer in discovery does not match the configured issuer');
      this.discovery = d;
    }
    return this.discovery;
  }

  // Where to send the browser, plus the cookie that remembers state, nonce and PKCE verifier.
  async start(secret: string, auth: AuthConfig): Promise<{ url: string; setCookie: string }> {
    const d = await this.discover();
    const st: OidcState = { state: b64url(randomBytes(16)), nonce: b64url(randomBytes(16)), verifier: b64url(randomBytes(32)), exp: now() + 600 };
    const challenge = b64url(createHash('sha256').update(st.verifier).digest());
    const q = new URLSearchParams({
      response_type: 'code', client_id: this.cfg.clientId, redirect_uri: this.redirectUri,
      scope: this.cfg.scopes.join(' '), state: st.state, nonce: st.nonce,
      code_challenge: challenge, code_challenge_method: 'S256',
    });
    return { url: `${d.authorization_endpoint}?${q}`, setCookie: cookie(OIDC_COOKIE, sign(st, secret), auth, 600) };
  }

  async finish(query: URLSearchParams, stateCookie: string | undefined, secret: string): Promise<Omit<Session, 'exp'>> {
    if (query.get('error')) throw new Error(`sign-in was refused: ${query.get('error_description') ?? query.get('error')}`);
    const st = unsign<OidcState>(stateCookie, secret);
    if (!st) throw new Error('sign-in expired; try again');
    if (!query.get('state') || !safeEqual(query.get('state')!, st.state)) throw new Error('sign-in state did not match; try again');
    const d = await this.discover();
    const tokens = await this.getJson<{ id_token?: string }>(d.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${encodeURIComponent(this.cfg.clientId)}:${encodeURIComponent(this.cfg.clientSecret)}`).toString('base64')}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: query.get('code') ?? '', redirect_uri: this.redirectUri, code_verifier: st.verifier }),
    });
    if (!tokens.id_token) throw new Error('OIDC: no id_token in the token response');
    const claims = await this.verifyIdToken(tokens.id_token, d, st.nonce);

    const raw = claims[this.cfg.groupsClaim];
    const groups: string[] = Array.isArray(raw) ? raw.map(String) : typeof raw === 'string' ? [raw] : [];
    if (this.cfg.allowedGroups.length && !groups.some(g => this.cfg.allowedGroups.includes(g)) && !groups.some(g => this.cfg.adminGroups.includes(g))) {
      throw new Error('your account is not in a group allowed to use teriac');
    }
    const role: Role = groups.some(g => this.cfg.adminGroups.includes(g)) ? 'admin' : 'viewer';
    const name = String(claims.name ?? claims.email ?? claims.preferred_username ?? claims.sub);
    const email = typeof claims.email === 'string' ? claims.email : undefined;
    return { sub: String(claims.sub), name, role, via: 'oidc', email, groups: groups.slice(0, 50) };
  }

  private async key(kid: string | undefined): Promise<Jwk> {
    const find = () => this.jwks.find(k => k.kty === 'RSA' && (!kid || k.kid === kid));
    if (!find()) {
      // Unknown key id: the provider may have rotated keys.
      const d = await this.discover();
      this.jwks = (await this.getJson<{ keys: Jwk[] }>(d.jwks_uri)).keys;
    }
    const k = find();
    if (!k) throw new Error('OIDC: no signing key matches the id_token');
    return k;
  }

  async verifyIdToken(token: string, d: Discovery, nonce: string): Promise<Record<string, any>> {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) throw new Error('OIDC: malformed id_token');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    if (header.alg !== 'RS256') throw new Error(`OIDC: id_token algorithm ${header.alg} is not allowed`);
    const jwk = await this.key(header.kid);
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${h}.${p}`);
    if (!verifier.verify(createPublicKey({ key: jwk as any, format: 'jwk' }), Buffer.from(s, 'base64url'))) {
      throw new Error('OIDC: id_token signature is invalid');
    }
    const c = JSON.parse(Buffer.from(p, 'base64url').toString());
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    const t = now();
    if (c.iss !== d.issuer) throw new Error('OIDC: id_token issuer mismatch');
    if (!aud.includes(this.cfg.clientId)) throw new Error('OIDC: id_token audience mismatch');
    if (typeof c.exp !== 'number' || c.exp < t - 60) throw new Error('OIDC: id_token expired');
    if (c.nonce !== nonce) throw new Error('OIDC: id_token nonce mismatch');
    return c;
  }
}

// ---- GitHub sign-in (the App's user authorization; code + PKCE) ---------------------------
//
// A GitHub App's user token can reach only repos that both the person and the App can, so
// "the repos this person may see in teriac" is exactly what GitHub lists for that token
// (then narrowed to the repos this server serves). Admins come from logins or teams.

export interface GitHubUserToken { access: string; refresh?: string; expires: number }

export interface GitHubSignIn {
  session: Omit<Session, 'exp'>;
  repos: string[];        // "host/owner/name"
  token: GitHubUserToken;
}

export interface GitHubLoginDeps {
  fetchImpl?: typeof fetch;
  serves: (repoKey: string) => boolean;                                  // in the server's allowlist
  inTeam: (repoKey: string, team: string, login: string) => Promise<boolean>; // via the App
}

export class GitHubLogin {
  readonly cfg: GitHubLoginConfig;
  private redirectUri: string;
  private d: GitHubLoginDeps;
  constructor(cfg: GitHubLoginConfig, publicUrl: string, d: GitHubLoginDeps) {
    this.cfg = cfg;
    this.redirectUri = `${publicUrl}/auth/github/callback`;
    this.d = d;
  }

  private fetch(url: string, init?: RequestInit) {
    return (this.d.fetchImpl ?? fetch)(url, { ...init, signal: AbortSignal.timeout(15_000) });
  }

  start(secret: string, auth: AuthConfig): { url: string; setCookie: string } {
    const st: OidcState = { state: b64url(randomBytes(16)), nonce: '', verifier: b64url(randomBytes(32)), exp: now() + 600 };
    const q = new URLSearchParams({
      client_id: this.cfg.clientId, redirect_uri: this.redirectUri, state: st.state, allow_signup: 'false',
      code_challenge: b64url(createHash('sha256').update(st.verifier).digest()), code_challenge_method: 'S256',
    });
    return { url: `${this.cfg.webUrl}/login/oauth/authorize?${q}`, setCookie: cookie(GITHUB_COOKIE, sign(st, secret), auth, 600) };
  }

  private async token(body: Record<string, string>): Promise<GitHubUserToken> {
    const res = await this.fetch(`${this.cfg.webUrl}/login/oauth/access_token`, {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: this.cfg.clientId, client_secret: this.cfg.clientSecret, ...body }),
    });
    const t = await res.json().catch(() => ({})) as { access_token?: string; refresh_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !t.access_token) throw new Error(`GitHub sign-in failed: ${t.error_description ?? t.error ?? `HTTP ${res.status}`}`);
    return { access: t.access_token, refresh: t.refresh_token, expires: Date.now() + (t.expires_in ?? 8 * 3600) * 1000 };
  }

  refresh(t: GitHubUserToken): Promise<GitHubUserToken> {
    if (!t.refresh) throw new Error('no refresh token');
    return this.token({ grant_type: 'refresh_token', refresh_token: t.refresh });
  }

  private async api<T>(token: string, path: string): Promise<{ data: T; next: string | null }> {
    const res = await this.fetch(path.startsWith('http') ? path : `${this.cfg.apiUrl}${path}`, {
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'teriac-server' },
    });
    if (res.status === 401) throw Object.assign(new Error('GitHub no longer accepts this sign-in'), { revoked: true });
    if (!res.ok) throw new Error(`GitHub ${path}: HTTP ${res.status}`);
    return { data: await res.json() as T, next: /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') ?? '')?.[1] ?? null };
  }

  // The repos this person can see through the App, that this server serves.
  async repos(token: string): Promise<string[]> {
    const out = new Set<string>();
    let next: string | null = '/user/installations?per_page=100';
    const installations: number[] = [];
    while (next) {
      const page: { data: { installations: { id: number }[] }; next: string | null } = await this.api(token, next);
      installations.push(...page.data.installations.map(i => i.id));
      next = page.next;
    }
    for (const id of installations) {
      let more: string | null = `/user/installations/${id}/repositories?per_page=100`;
      while (more) {
        const page: { data: { repositories: { full_name: string }[] }; next: string | null } = await this.api(token, more);
        for (const r of page.data.repositories) {
          const key = `${this.cfg.host}/${r.full_name}`;
          if (this.d.serves(key)) out.add(key);
        }
        more = page.next;
      }
    }
    return [...out].sort();
  }

  // Admin (by login or team), or viewer; null when not allowed to sign in at all.
  async role(login: string, repos: string[]): Promise<Role | null> {
    const lower = login.toLowerCase();
    const teamOf = async (teams: string[]) => {
      for (const team of teams) {
        const org = team.split('/')[0].toLowerCase();
        const repo = repos.find(r => r.split('/')[1]?.toLowerCase() === org);
        if (repo && await this.d.inTeam(repo, team, login).catch(() => false)) return true;
      }
      return false;
    };
    if (this.cfg.adminUsers.some(u => u.toLowerCase() === lower) || await teamOf(this.cfg.adminTeams)) return 'admin';
    if (!repos.length) return null;
    if (this.cfg.allowedTeams.length && !(await teamOf(this.cfg.allowedTeams))) return null;
    return 'viewer';
  }

  async finish(query: URLSearchParams, stateCookie: string | undefined, secret: string): Promise<GitHubSignIn> {
    if (query.get('error')) throw new Error(`sign-in was refused: ${query.get('error_description') ?? query.get('error')}`);
    const st = unsign<OidcState>(stateCookie, secret);
    if (!st) throw new Error('sign-in expired; try again');
    if (!query.get('state') || !safeEqual(query.get('state')!, st.state)) throw new Error('sign-in state did not match; try again');
    const token = await this.token({ code: query.get('code') ?? '', redirect_uri: this.redirectUri, code_verifier: st.verifier });
    const { data: user } = await this.api<{ login: string; name?: string | null; email?: string | null }>(token.access, '/user');
    const repos = await this.repos(token.access);
    const role = await this.role(user.login, repos);
    if (!role) {
      throw new Error(repos.length
        ? 'your GitHub account is not in a team allowed to use teriac'
        : 'your GitHub account can\'t see any repository this teriac serves');
    }
    return {
      session: { sub: `github:${user.login.toLowerCase()}`, name: user.login, login: user.login, role, via: 'github', email: user.email ?? undefined },
      repos, token,
    };
  }
}
