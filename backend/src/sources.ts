import type { SourceName, SourceWorker } from "./types";
import { fetchWithRetry, getJson, labelsToHosts, escapeRegex } from "./helpers";

// ---------- 1) crt.sh ----------
const crtsh: SourceWorker = {
  name: "crtsh",
  enabled: () => true,
  async fetch(domain) {
    const url = `https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`;
    const rows = await getJson<{ name_value: string }[]>(url, {}, { retries: 2, timeoutMs: 30000 });
    return rows.map((r) => r.name_value);
  },
};

// ---------- 2) Wayback Machine ----------
const wayback: SourceWorker = {
  name: "wayback",
  enabled: () => true,
  async fetch(domain) {
    const url =
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}` +
      `&matchType=domain&output=json&fl=original&collapse=urlkey&limit=2000`;
    const rows = await getJson<string[][]>(
      url,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; HiddenOSINT/1.0)",
          Accept: "application/json",
        },
      },
      { retries: 0, timeoutMs: 20000 }
    );
    const hosts = new Set<string>();
    for (const row of rows.slice(1)) {
      try {
        hosts.add(new URL(row[0]).hostname);
      } catch {
        /* تجاهل الروابط المكسورة */
      }
    }
    return [...hosts];
  },
};
// ---------- 3) GitHub ----------
interface CodeSearch {
  items?: { text_matches?: { fragment: string }[] }[];
}

const github: SourceWorker = {
  name: "github",
  enabled: (env) => !!env.GITHUB_TOKEN,
  async fetch(domain, env) {
    const re = new RegExp(`[a-z0-9_.-]+\\.${escapeRegex(domain)}`, "gi");
    const found = new Set<string>();

    for (let page = 1; page <= 3; page++) {
      const res = await fetchWithRetry(
        `https://api.github.com/search/code?q=${encodeURIComponent(`"${domain}"`)}&per_page=100&page=${page}`,
        {
          headers: {
            Authorization: `Bearer ${env.GITHUB_TOKEN}`,
            Accept: "application/vnd.github.text-match+json",
            "User-Agent": "osint-engine",
          },
        }
      );
      if (!res.ok) throw new Error(`HTTP ${res.status} from api.github.com`);
      const body = (await res.json()) as CodeSearch;
      const items = body.items ?? [];
      for (const item of items)
        for (const m of item.text_matches ?? [])
          for (const hit of m.fragment.match(re) ?? []) found.add(hit);
      if (items.length < 100) break;
    }
    return [...found];
  },
};

// ---------- 4) VirusTotal ----------
interface VtPage {
  data?: { id: string }[];
  links?: { next?: string };
}

const virustotal: SourceWorker = {
  name: "virustotal",
  enabled: (env) => !!env.VIRUSTOTAL_API_KEY,
  async fetch(domain, env) {
    const out: string[] = [];
    let url: string | undefined = `https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=40`;
    for (let i = 0; i < 5 && url; i++) {
      const page: VtPage = await getJson<VtPage>(url, {
        headers: { "x-apikey": env.VIRUSTOTAL_API_KEY! },
      });
      out.push(...(page.data ?? []).map((d) => d.id));
      url = page.links?.next;
    }
    return out;
  },
};

// ---------- 5) SecurityTrails ----------
const securitytrails: SourceWorker = {
  name: "securitytrails",
  enabled: (env) => !!env.SECURITYTRAILS_API_KEY,
  async fetch(domain, env) {
    const data = await getJson<{ subdomains?: string[] }>(
      `https://api.securitytrails.com/v1/domain/${domain}/subdomains?children_only=false&include_inactive=true`,
      { headers: { APIKEY: env.SECURITYTRAILS_API_KEY! } }
    );
    return labelsToHosts(data.subdomains ?? [], domain);
  },
};

// ---------- 6) Shodan ----------
const shodan: SourceWorker = {
  name: "shodan",
  enabled: (env) => !!env.SHODAN_API_KEY,
  async fetch(domain, env) {
    const data = await getJson<{ subdomains?: string[] }>(
      `https://api.shodan.io/dns/domain/${domain}?key=${env.SHODAN_API_KEY}`
    );
    return labelsToHosts(data.subdomains ?? [], domain);
  },
};

// ---------- 7) Censys (راجع الـ docs بتاعة حسابك، الـ API بيتغير) ----------
interface CensysCerts {
  result?: { hits?: { names?: string[] }[]; links?: { next?: string } };
}

const censys: SourceWorker = {
  name: "censys",
  enabled: (env) => !!env.CENSYS_API_ID && !!env.CENSYS_API_SECRET,
  async fetch(domain, env) {
    const auth = "Basic " + btoa(`${env.CENSYS_API_ID}:${env.CENSYS_API_SECRET}`);
    const out: string[] = [];
    let cursor: string | undefined;

    for (let i = 0; i < 3; i++) {
      const res = await fetchWithRetry("https://search.censys.io/api/v2/certificates/search", {
        method: "POST",
        headers: { Authorization: auth, "Content-Type": "application/json" },
        body: JSON.stringify({
          q: `names: ${domain}`,
          per_page: 100,
          ...(cursor ? { cursor } : {}),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from search.censys.io`);
      const body = (await res.json()) as CensysCerts;
      for (const hit of body.result?.hits ?? []) out.push(...(hit.names ?? []));
      cursor = body.result?.links?.next;
      if (!cursor) break;
    }
    return out;
  },
};

export const SOURCES: Record<SourceName, SourceWorker> = {
  crtsh,
  wayback,
  github,
  virustotal,
  securitytrails,
  shodan,
  censys,
};

export const ALL_SOURCES = Object.keys(SOURCES) as SourceName[];