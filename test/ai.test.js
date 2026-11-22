const fs = require('fs');
const os = require('os');
const path = require('path');
const ai = require('../lib/modules/ai');

// A fake Claude client: answers with `answer` and records what was sent.
const fakeClient = (answer, stop = 'end_turn') => {
  const sent = [];
  return {
    sent,
    provider: 'anthropic',
    model: 'claude-opus-5-5',
    api: { beta: { messages: { create: async (p) => { sent.push(p); return { stop_reason: stop, content: [{ type: 'text', text: JSON.stringify(answer) }] }; } } } },
  };
};

const plan = {
  resource_changes: [
    { address: 'aws_db_instance.main', change: { actions: ['delete', 'create'], replace_paths: [['engine_version']],
      before: { engine_version: '14', password: 'hunter2-SUPERSECRET' }, after: { engine_version: '16', password: 'hunter2-SUPERSECRET' },
      after_unknown: {}, before_sensitive: { password: true }, after_sensitive: { password: true } } },
    { address: 'aws_s3_bucket.logs', change: { actions: ['no-op'], before: {}, after: {} } },
  ],
};

describe('AI help in the CLI', () => {
  test('sensitive values and secrets are hidden before sending', async () => {
    const c = fakeClient({ summary: 'Replaces the database.', findings: [] });
    const r = await ai.review(c, plan, 'prod');
    expect(r.summary).toBe('Replaces the database.');
    const body = JSON.stringify(c.sent[0]);
    expect(body).not.toContain('hunter2-SUPERSECRET');
    expect(body).toContain('(sensitive value)');
    expect(body).toContain('aws_db_instance.main');
    expect(body).not.toContain('aws_s3_bucket.logs');
    expect(body).toContain('"fallbacks":"default"');
    expect(ai.hideSecrets('token ghp_' + 'a'.repeat(36) + ' and password = "letmein1"')).toBe('token ‹redacted› and password = "‹redacted›"');
  });

  test('a declined request is an error the command reports', async () => {
    await expect(ai.review(fakeClient({}, 'refusal'), plan, 'x')).rejects.toThrow(/declined/);
  });

  test('fixes outside the folder or past the end are dropped; the rest can be written', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'teriac-ai-'));
    try {
      fs.writeFileSync(path.join(dir, 'main.tf'), 'resource "x" "y" {\n  input = var.missing\n}\n');
      const c = fakeClient({ cause: 'var.missing is not declared.', fixes: [
        { path: 'main.tf', start_line: 2, end_line: 2, replacement: '  input = "fixed"\n', why: 'use a value' },
        { path: '../etc/passwd', start_line: 1, end_line: 1, replacement: 'x', why: 'no' },
        { path: 'main.tf', start_line: 40, end_line: 41, replacement: 'x', why: 'past the end' },
      ] });
      const r = await ai.diagnose(c, 'Error: Reference to undeclared input variable', dir);
      expect(r.fixes.map(f => f.path)).toEqual(['main.tf']);
      expect(JSON.stringify(c.sent[0])).toContain('2|   input = var.missing');
      ai.applyFixes(dir, r.fixes);
      expect(fs.readFileSync(path.join(dir, 'main.tf'), 'utf8')).toBe('resource "x" "y" {\n  input = "fixed"\n}\n');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('needs a key, and names the fix', () => {
    expect(() => ai.client({})).toThrow(/ANTHROPIC_API_KEY/);
    expect(() => ai.client({ TERIAC_AI_PROVIDER: 'openai' })).toThrow(/anthropic, bedrock or vertex/);
  });
});
