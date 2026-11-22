// AI settings: the server's provider and model (TERIAC_AI_*), and the `ai:` blocks of repos.yaml
// and teriac.yaml that turn it on or off per repo and project. Kept apart from ai.ts so the
// config loaders don't pull in the policy engine.
export type AiProvider = 'anthropic' | 'bedrock' | 'vertex' | 'foundry';
export const AI_PROVIDERS: AiProvider[] = ['anthropic', 'bedrock', 'vertex', 'foundry'];
export type AiFeature = 'review' | 'fix' | 'drift' | 'policy' | 'ask';
export const AI_FEATURES: AiFeature[] = ['review', 'fix', 'drift', 'policy', 'ask'];
export type AiEffort = 'low' | 'medium' | 'high' | 'xhigh' | 'max';
const EFFORTS: AiEffort[] = ['low', 'medium', 'high', 'xhigh', 'max'];

export interface AiConfig {
  provider: AiProvider;
  model: string;
  effort: AiEffort;
  features: AiFeature[];
  timeoutMs: number;
}

export const DEFAULT_MODEL = 'claude-opus-5-5';

// TERIAC_AI_PROVIDER turns it on. Credentials come from each provider's usual place:
// ANTHROPIC_API_KEY; the AWS credential chain and AWS_REGION; Google ADC with
// ANTHROPIC_VERTEX_PROJECT_ID and CLOUD_ML_REGION; ANTHROPIC_FOUNDRY_RESOURCE and ANTHROPIC_FOUNDRY_API_KEY.
export const loadAiConfig = (env: NodeJS.ProcessEnv): AiConfig | undefined => {
  const provider = (env.TERIAC_AI_PROVIDER ?? '').trim().toLowerCase();
  if (!provider || provider === 'off') return undefined;
  if (!AI_PROVIDERS.includes(provider as AiProvider)) throw new Error(`TERIAC_AI_PROVIDER must be one of ${AI_PROVIDERS.join(', ')} or off, not "${env.TERIAC_AI_PROVIDER}"`);
  const effort = (env.TERIAC_AI_EFFORT || 'medium').trim().toLowerCase();
  if (!EFFORTS.includes(effort as AiEffort)) throw new Error(`TERIAC_AI_EFFORT must be one of ${EFFORTS.join(', ')}, not "${env.TERIAC_AI_EFFORT}"`);
  const features = (env.TERIAC_AI_FEATURES || AI_FEATURES.join(',')).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  for (const f of features) if (!AI_FEATURES.includes(f as AiFeature)) throw new Error(`TERIAC_AI_FEATURES: unknown feature "${f}" (${AI_FEATURES.join(', ')})`);
  if (provider === 'vertex' && !env.ANTHROPIC_VERTEX_PROJECT_ID) throw new Error('TERIAC_AI_PROVIDER=vertex needs ANTHROPIC_VERTEX_PROJECT_ID (and CLOUD_ML_REGION, default "global")');
  if (provider === 'bedrock' && !(env.AWS_REGION || env.AWS_DEFAULT_REGION)) throw new Error('TERIAC_AI_PROVIDER=bedrock needs AWS_REGION');
  const model = env.TERIAC_AI_MODEL?.trim() || (provider === 'bedrock' ? `anthropic.${DEFAULT_MODEL}` : DEFAULT_MODEL);
  return {
    provider: provider as AiProvider, model, effort: effort as AiEffort, features: features as AiFeature[],
    timeoutMs: Math.max(10, Number(env.TERIAC_AI_TIMEOUT_SECONDS || 180)) * 1000,
  };
};

// ---- where AI is on: repos.yaml (server, repo entry, project rule) and teriac.yaml ----

// An `ai:` block. In repos.yaml it can turn AI on or off and change the features, model and
// effort; TERIAC_AI_FEATURES stays the ceiling. In teriac.yaml it can only turn AI off or drop
// features: the server's owner pays for the requests.
export interface AiOverride { enabled?: boolean; features?: AiFeature[]; model?: string; effort?: AiEffort }
// What applies to one project; null when AI is off for it.
export interface AiSettings { features: AiFeature[]; model: string; effort: AiEffort }

export const validateAiOverride = (v: unknown, where: string): AiOverride | undefined => {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'boolean') return { enabled: v };   // `ai: false` is short for `ai: { enabled: false }`
  if (typeof v !== 'object' || Array.isArray(v)) throw new Error(`${where} must be true, false or { enabled, features, model, effort }`);
  const o = v as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['enabled', 'features', 'model', 'effort'].includes(k)) throw new Error(`${where}: unknown setting "${k}" (enabled, features, model, effort)`);
  if (o.enabled !== undefined && typeof o.enabled !== 'boolean') throw new Error(`${where}.enabled must be true or false`);
  if (o.features !== undefined) {
    if (!Array.isArray(o.features)) throw new Error(`${where}.features must be a list of ${AI_FEATURES.join(', ')}`);
    for (const f of o.features) if (!AI_FEATURES.includes(f as AiFeature)) throw new Error(`${where}.features: unknown feature "${f}" (${AI_FEATURES.join(', ')})`);
  }
  if (o.model !== undefined && (typeof o.model !== 'string' || !o.model.trim())) throw new Error(`${where}.model must be a model name`);
  if (o.effort !== undefined && !EFFORTS.includes(o.effort as AiEffort)) throw new Error(`${where}.effort must be one of ${EFFORTS.join(', ')}`);
  return o as AiOverride;
};

// Layers in order; later ones win. Server layers: repos.yaml's top-level `ai`, the repo entry's,
// the first matching project rule that has one. Repo layers (teriac.yaml) only narrow.
export const resolveAi = (cfg: AiConfig | undefined, server: (AiOverride | undefined)[], repo: (AiOverride | undefined)[] = []): AiSettings | null => {
  if (!cfg) return null;
  let enabled = true;
  let features = [...cfg.features];
  let model = cfg.model;
  let effort = cfg.effort;
  for (const o of server) {
    if (!o) continue;
    if (o.enabled !== undefined) enabled = o.enabled;
    if (o.features) features = cfg.features.filter(f => o.features!.includes(f));
    if (o.model) model = cfg.provider === 'bedrock' && !o.model.startsWith('anthropic.') ? `anthropic.${o.model}` : o.model;
    if (o.effort) effort = o.effort;
  }
  for (const o of repo) {
    if (!o) continue;
    if (o.enabled === false) enabled = false;
    if (o.features) features = features.filter(f => o.features!.includes(f));
  }
  return enabled && features.length ? { features, model, effort } : null;
};

// The model's name as shown on comments and the dashboard.
export const label = (s: AiSettings) => s.model.replace(/^anthropic\./, '');

// Review findings worth a person's attention in the PR; low ones stay on the check run and dashboard.
export const important = (f: { severity: string }) => f.severity !== 'low';
