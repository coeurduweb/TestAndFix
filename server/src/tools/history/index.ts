// Unified history of one notebook (owner.ts): tool results and mail tests of the retention window.
// A row of another notebook (or a legacy row without notebook) answers like a missing one.
import type { ServerTool } from '../types.js';
import { intParam, likeContains } from '../../lib/params.js';

interface Row {
  id: string;
  tool: string;
  input: string;
  created_at: number;
  score: number | null;
  summary: string | null;
}

export const tool: ServerTool = {
  id: 'history',
  register(app, ctx) {
    app.get<{ Querystring: { tool?: string; q?: string; limit?: string; offset?: string } }>('/api/history', async (req) => {
      const owner = req.owner?.ownerId ?? null;
      const limit = intParam(req.query.limit, 50, 1, 200);
      const offset = intParam(req.query.offset, 0, 0, 1_000_000);
      const where: string[] = [];
      const args: unknown[] = [];
      if (req.query.tool) {
        where.push('tool = ?');
        args.push(req.query.tool);
      }
      if (req.query.q) {
        where.push("input LIKE ? ESCAPE '\\'");
        args.push(likeContains(req.query.q.toLowerCase()));
      }
      const results = ctx.db
        .prepare(
          `SELECT id, tool, input, created_at, score, summary FROM (
             SELECT id, tool, input, created_at, score, summary FROM results WHERE owner_id = ?
             UNION ALL
             SELECT id, 'mail' AS tool, COALESCE(from_addr, subject, '') AS input, created_at, score,
                    json_object('subject', subject, 'via', via, 'addressId', address_id, 'status', status) AS summary
             FROM mail_messages WHERE owner_id = ?
           ) ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
           ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        )
        .all(owner, owner, ...args, limit, offset) as Row[];
      const total = (
        ctx.db
          .prepare(
            `SELECT COUNT(*) AS n FROM (SELECT tool, input FROM results WHERE owner_id = ? UNION ALL SELECT 'mail' AS tool, COALESCE(from_addr, subject, '') AS input FROM mail_messages WHERE owner_id = ?) ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`,
          )
          .get(owner, owner, ...args) as { n: number }
      ).n;
      return {
        total,
        items: results.map((r) => ({
          id: r.id,
          tool: r.tool,
          input: r.input,
          at: new Date(r.created_at).toISOString(),
          score: r.score,
          summary: r.summary ? JSON.parse(r.summary) : null,
        })),
      };
    });
    app.get<{ Params: { id: string } }>('/api/history/:id', async (req, reply) => {
      const row = ctx.db
        .prepare('SELECT id, tool, input, created_at, score, data FROM results WHERE id = ? AND owner_id = ?')
        .get(req.params.id, req.owner?.ownerId ?? null) as
        | (Row & { data: string })
        | undefined;
      if (!row) return reply.code(404).send({ error: 'not_found' });
      return { id: row.id, tool: row.tool, input: row.input, at: new Date(row.created_at).toISOString(), score: row.score, result: JSON.parse(row.data) };
    });
    // one result, or one mail test (ids "m-…"), of this notebook
    app.delete<{ Params: { id: string } }>('/api/history/:id', async (req, reply) => {
      const owner = req.owner?.ownerId ?? null;
      const id = req.params.id;
      const done = ctx.db.transaction(() => {
        if (id.startsWith('m-')) {
          const n = ctx.db.prepare('DELETE FROM mail_messages WHERE id = ? AND owner_id = ?').run(id, owner).changes;
          if (n) ctx.db.prepare("DELETE FROM shares WHERE kind = 'mail-message' AND target_id = ?").run(id);
          return n;
        }
        return ctx.db.prepare('DELETE FROM results WHERE id = ? AND owner_id = ?').run(id, owner).changes;
      })();
      if (!done) return reply.code(404).send({ error: 'not_found' });
      return reply.code(204).send();
    });
    app.get('/api/history/stats', async (req) => {
      const owner = req.owner?.ownerId ?? null;
      const r = ctx.db.prepare('SELECT MIN(created_at) AS oldest, COUNT(*) AS n FROM results WHERE owner_id = ?').get(owner) as {
        oldest: number | null;
        n: number;
      };
      const m = ctx.db.prepare('SELECT COUNT(*) AS n FROM mail_messages WHERE owner_id = ?').get(owner) as { n: number };
      return { results: r.n, mails: m.n, oldest: r.oldest ? new Date(r.oldest).toISOString() : null, retentionDays: ctx.config.retentionDays };
    });
  },
};
