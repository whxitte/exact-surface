// Derive a severity + human "reason" for an open port. Ports themselves carry no
// severity from the scanner, so we grade by exposure risk: a directly-reachable
// database/cache is critical, remote-admin is high, web/DNS is informational.

const CRITICAL_PORTS: Record<number, string> = {
  3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB",
  9200: "Elasticsearch", 11211: "Memcached", 1433: "MSSQL", 1521: "Oracle",
  5984: "CouchDB", 9000: "Portainer/PHP-FPM", 2379: "etcd",
};
const HIGH_PORTS: Record<number, string> = {
  22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB",
  135: "MSRPC", 139: "NetBIOS", 21: "FTP", 2049: "NFS",
};
const KNOWN: Record<number, string> = {
  53: "DNS", 80: "HTTP", 443: "HTTPS", 25: "SMTP", 110: "POP3", 143: "IMAP",
  587: "SMTP", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-alt", 8443: "HTTPS-alt",
};

export function portSeverity(port: number): "critical" | "high" | "medium" | "info" {
  if (port in CRITICAL_PORTS) return "critical";
  if (port in HIGH_PORTS) return "high";
  if (port === 25 || port === 587) return "medium";
  return "info";
}

/** A short "why this matters" label — DNS / HTTPS / SSH / MySQL … */
export function portReason(port: number, service?: string | null): string {
  return (
    CRITICAL_PORTS[port] ||
    HIGH_PORTS[port] ||
    KNOWN[port] ||
    (service ? service.toUpperCase() : `TCP ${port}`)
  );
}
