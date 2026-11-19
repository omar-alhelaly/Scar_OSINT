export type SourceName =
  | "crtsh"
  | "wayback"
  | "github"
  | "virustotal"
  | "securitytrails"
  | "shodan"
  | "censys";

export interface Env {
  DB: D1Database;
  SCAN_QUEUE: Queue<ScanJob>;
  API_TOKEN?: string;
  VIRUSTOTAL_API_KEY?: string;
  SECURITYTRAILS_API_KEY?: string;
  SHODAN_API_KEY?: string;
  CENSYS_API_ID?: string;
  CENSYS_API_SECRET?: string;
  GITHUB_TOKEN?: string;
}

export interface ScanJob {
  scanId: string;
  domain: string;
  source: SourceName;
}

export interface SourceWorker {
  name: SourceName;
  enabled(env: Env): boolean;
  fetch(domain: string, env: Env): Promise<string[]>;
}