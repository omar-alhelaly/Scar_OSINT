import type { Env, ScanJob } from "./types";
import { ALL_SOURCES, SOURCES } from "./sources";
import { cleanRootDomain, normalizeSubdomains } from "./helpers";

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });

function authorized(req: Request, env: Env): boolean {
  if (!env.API_TOKEN) return true;
  return req.headers.get("Authorization") === `Bearer ${env.API_TOKEN}`;
}

export default {
  // ---------- الـ API ----------
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Authorization, Content-Type",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
      });
    }
    if (!authorized(req, env)) return json({ error: "unauthorized" }, 401);

    // POST /api/scans  { "domain": "example.com" }
    if (req.method === "POST" && url.pathname === "/api/scans") {
      const body = (await req.json().catch(() => ({}))) as { domain?: string };
      const domain = cleanRootDomain(body.domain);
      if (!domain) return json({ error: "invalid domain" }, 400);

      const scanId = crypto.randomUUID();
      const jobs: ScanJob[] = [];
      const stmts = [
        env.DB.prepare("INSERT INTO scans (id, domain) VALUES (?, ?)").bind(scanId, domain),
      ];

      for (const name of ALL_SOURCES) {
        const on = SOURCES[name].enabled(env);
        stmts.push(
          env.DB.prepare(
            "INSERT INTO scan_sources (scan_id, source, status, error) VALUES (?, ?, ?, ?)"
          ).bind(scanId, name, on ? "pending" : "skipped", on ? null : "missing API key")
        );
        if (on) jobs.push({ scanId, domain, source: name });
      }
      await env.DB.batch(stmts);
      await env.SCAN_QUEUE.sendBatch(jobs.map((body) => ({ body })));

      return json({ scanId, domain, sources: jobs.map((j) => j.source) }, 202);
    }

    // GET /api/scans/:id
    const m = url.pathname.match(/^\/api\/scans\/([0-9a-f-]{36})$/);
    if (req.method === "GET" && m) {
      const id = m[1];
      const scan = await env.DB.prepare("SELECT * FROM scans WHERE id = ?")
        .bind(id)
        .first<{ domain: string; created_at: string }>();
      if (!scan) return json({ error: "not found" }, 404);

      const [sources, subs] = await Promise.all([
        env.DB.prepare("SELECT source, status, found, error FROM scan_sources WHERE scan_id = ?")
          .bind(id)
          .all(),
        env.DB.prepare("SELECT subdomain, sources FROM subdomains WHERE scan_id = ? ORDER BY subdomain")
          .bind(id)
          .all<{ subdomain: string; sources: string }>(),
      ]);
      const finished = sources.results.every((s) => s.status !== "pending");

      return json({
        scanId: id,
        domain: scan.domain,
        createdAt: scan.created_at,
        status: finished ? "complete" : "running",
        sources: sources.results,
        total: subs.results.length,
        subdomains: subs.results.map((r) => ({
          subdomain: r.subdomain,
          sources: r.sources.split(","),
        })),
      });
    }

    if (url.pathname === "/")
      return json({ name: "osint-engine", endpoints: ["POST /api/scans", "GET /api/scans/:id"] });
    return json({ error: "not found" }, 404);
  },

  // ---------- مستهلك الـ Queue ----------
  async queue(batch: MessageBatch<ScanJob>, env: Env): Promise<void> {
    await Promise.all(
      batch.messages.map(async (msg) => {
        const { scanId, domain, source } = msg.body;
        try {
          const raw = await SOURCES[source].fetch(domain, env);
          const hosts = normalizeSubdomains(raw, domain);

          const stmts = hosts.map((h) =>
            env.DB.prepare(
              `INSERT INTO subdomains (scan_id, subdomain, sources) VALUES (?, ?, ?)
               ON CONFLICT(scan_id, subdomain) DO UPDATE SET
                 sources = CASE WHEN (',' || sources || ',') LIKE ('%,' || excluded.sources || ',%')
                                THEN sources ELSE sources || ',' || excluded.sources END`
            ).bind(scanId, h, source)
          );
          for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));

          await env.DB.prepare(
            "UPDATE scan_sources SET status='done', found=?, error=NULL, updated_at=datetime('now') WHERE scan_id=? AND source=?"
          )
            .bind(hosts.length, scanId, source)
            .run();
          msg.ack();
        } catch (err) {
                    const message = err instanceof Error ? err.message : String(err);
          const permanent = /^HTTP (400|401|403|404) /.test(message);
          if (permanent || msg.attempts >= 3) {
            await env.DB.prepare(
              "UPDATE scan_sources SET status='failed', error=?, updated_at=datetime('now') WHERE scan_id=? AND source=?"
            )
              .bind(message.slice(0, 300), scanId, source)
              .run();
            msg.ack();
          } else {
            msg.retry({ delaySeconds: 10 * msg.attempts });
          }
        }
      })
    );
  },
};