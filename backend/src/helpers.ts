// ---------- HTTP مع إعادة المحاولة ----------
interface RetryOptions {
  retries?: number;
  timeoutMs?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function fetchWithRetry(
  url: string,
  init: RequestInit = {},
  { retries = 2, timeoutMs = 20000 }: RetryOptions = {}
): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (res.status === 429 || res.status >= 500) {
        if (attempt === retries) return res;
        const retryAfter = Number(res.headers.get("Retry-After"));
        const wait = retryAfter > 0 ? retryAfter * 1000 : 1000 * 2 ** attempt;
        await sleep(Math.min(wait, 8000));
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt === retries) break;
      await sleep(1000 * 2 ** attempt);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("fetch failed");
}

export async function getJson<T>(
  url: string,
  init: RequestInit = {},
  opts?: RetryOptions
): Promise<T> {
  const res = await fetchWithRetry(url, init, opts);
  if (!res.ok) {
    const body = (await res.text().catch(() => "")).replace(/\s+/g, " ").slice(0, 160);
    throw new Error(`HTTP ${res.status} from ${new URL(url).hostname}${body ? `: ${body}` : ""}`);
  }
  return (await res.json()) as T;
}


// ---------- تنضيف الدومينات ----------
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const ROOT_DOMAIN =
  /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function cleanRootDomain(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const d = input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "");
  return ROOT_DOMAIN.test(d) ? d : null;
}

export function normalizeSubdomains(raw: string[], root: string): string[] {
  const out = new Set<string>();
  const suffix = "." + root;

  for (const chunk of raw) {
    for (const part of String(chunk).split(/[\s,]+/)) {
      let h = part.trim().toLowerCase();
      if (!h) continue;
      h = h.replace(/^\*\./, "").replace(/^\*+/, "").replace(/\.$/, "");
      h = h.replace(/:\d+$/, "");
      if (h.includes("@")) h = h.split("@").pop()!;
      if (h !== root && !h.endsWith(suffix)) continue;
      if (h.length > 253) continue;
      if (!h.split(".").every((l) => LABEL.test(l))) continue;
      out.add(h);
    }
  }
  return [...out].sort();
}

export const labelsToHosts = (labels: string[], root: string) =>
  labels.map((l) => `${l}.${root}`);

export const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");