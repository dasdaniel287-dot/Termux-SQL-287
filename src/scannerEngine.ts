/**
 * SQLGuard AI - Web Scanner & Simulation Engine
 * Mirrors the Python safe scanner, error detection signatures, and SQLite demonstration.
 */

export interface FindingItem {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational";
  confidence: "Confirmed" | "High" | "Medium" | "Low";
  category: string;
  endpoint: string;
  parameter: string | null;
  description: string;
  evidence: string;
  remediation: string;
  secure_code_example: string;
  verification_steps: string;
  timestamp: string;
  dbms_detected?: string;
  technical_details?: Record<string, any>;
}

export interface ScanRunResult {
  target: string;
  mode: "passive" | "safe-active";
  duration: number;
  findings: FindingItem[];
  logEntries: string[];
}

export const DBMS_ERROR_SIGNATURES: Record<string, { pattern: RegExp; example: string }> = {
  SQLite: {
    pattern: /(sqlite3\.(OperationalError|DatabaseError)|near\s+["'][^"']*["']:\s+syntax\s+error|unrecognized\s+token|incomplete\s+input|no\s+such\s+table)/i,
    example: "sqlite3.OperationalError: near \"'\": syntax error",
  },
  "MySQL / MariaDB": {
    pattern: /(You have an error in your SQL syntax|check the manual that corresponds to your (MySQL|MariaDB)|Warning: mysql_|MySqlException)/i,
    example: "You have an error in your SQL syntax near '' at line 1",
  },
  PostgreSQL: {
    pattern: /(ERROR:\s+syntax\s+error\s+at\s+or\s+near|psycopg2\.(errors\.)?[A-Za-z]+|pg_query\(\):\s+Query\s+failed|PSQLException)/i,
    example: "ERROR: syntax error at or near \"'\" at character 38",
  },
  "Microsoft SQL Server": {
    pattern: /(Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|SqlException)/i,
    example: "Unclosed quotation mark after the character string '''.",
  },
  Oracle: {
    pattern: /(ORA-00933|ORA-00907|ORA-01756|Oracle error)/i,
    example: "ORA-00933: SQL command not properly ended",
  },
};

export const COMMON_SQL_PARAMS = new Set([
  "id", "user", "userid", "user_id", "username", "cat", "category",
  "item", "product", "search", "q", "query", "filter", "sort",
  "order", "orderby", "page", "limit", "offset", "column"
]);

export function redactSensitiveUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl.startsWith("http") ? rawUrl : `http://${rawUrl}`);
    const sensitive = ["password", "token", "secret", "auth", "session", "api_key", "pin"];
    for (const key of Array.from(url.searchParams.keys())) {
      if (sensitive.some((s) => key.toLowerCase().includes(s))) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }
    return url.toString();
  } catch {
    return rawUrl;
  }
}

export function validateTargetSafety(urlStr: string, allowLocalLab: boolean): { safe: boolean; error?: string; message: string } {
  try {
    const url = new URL(urlStr.startsWith("http") ? urlStr : `http://${urlStr}`);
    const host = url.hostname.toLowerCase();
    const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "::1";
    const isPrivate =
      isLoopback ||
      host.startsWith("192.168.") ||
      host.startsWith("10.") ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);

    if (isPrivate) {
      if (!allowLocalLab) {
        return {
          safe: false,
          error: `Blocked SSRF/Private target '${host}'. Private network targets are restricted unless Local Lab mode is explicitly authorized.`,
          message: "Private address access blocked.",
        };
      }
      return {
        safe: true,
        message: `Target '${host}' approved under Controlled Local Lab policy.`,
      };
    }

    return {
      safe: true,
      message: `Target '${host}' validated for authorized assessment.`,
    };
  } catch {
    return {
      safe: false,
      error: `Invalid URL format: '${urlStr}'`,
      message: "Malformed URL.",
    };
  }
}
