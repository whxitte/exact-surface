/**
 * Static demo fixtures — the entire "backend" of the demo site.
 *
 * Generated fictional data confined to demo.exactsurface.com, so nothing here points
 * at a real third party. A demo showing findings against somebody else's domain would
 * be exactly what this product exists to warn people about.
 */

export const PROGRAM = {
  "program_id": "prog_demo",
  "apex_domain": "demo.exactsurface.com",
  "verified": true,
  "enabled": true,
  "scan_shared_infra": false,
  "enabled_modules": [
    "tls",
    "param_discovery",
    "typosquat"
  ],
  "verification_method": "dns_txt",
  "created_at": "2026-05-03T08:07:57.295148+00:00"
} as const;

export const ASSETS = [
  {
    "fingerprint": "3d6f8631126d3be1958837769e4b9d66",
    "hostname": "demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.10"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "low",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.10"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-03T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": true,
    "gone": false
  },
  {
    "fingerprint": "96dad933b5e22543b545bc3a69b7321d",
    "hostname": "www.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.10"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "low",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.10"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-04T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": true,
    "gone": false
  },
  {
    "fingerprint": "d2109e8afeb127f43838194d4938652f",
    "hostname": "api.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.11"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "high",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.11"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-05T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "18922d4dd2369fb5908eb3541c49905f",
    "hostname": "staging.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.12"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": true,
    "monitored": true,
    "interest": "critical",
    "interest_reasons": [
      "Exposed staging environment"
    ],
    "dns_records": {
      "a": [
        "203.0.113.12"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-06T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "0c1a042a32c093bd033bae13a5812459",
    "hostname": "admin.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.13"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "critical",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.13"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-07T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "e731d1b09695d31014f51441b2021845",
    "hostname": "jenkins.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.14"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "critical",
    "interest_reasons": [
      "Jenkins CI/CD exposed"
    ],
    "dns_records": {
      "a": [
        "203.0.113.14"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-08T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "429a2cae76bcde534ef6ec9260506950",
    "hostname": "mail.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.15"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "medium",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.15"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-09T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "97bcad895c945759bf5a9f67fbd52d6f",
    "hostname": "vpn.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.16"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "high",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.16"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-10T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "0d31e73f853b39e24cacf657e6d383e5",
    "hostname": "blog.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.17"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "medium",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.17"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-11T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "075cc09b84f7c8d5912e8e57a88631bc",
    "hostname": "legacy.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.18"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "high",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.18"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-12T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "597bf0235d0f27b01b7081fb6b6b24a0",
    "hostname": "cdn.demo.exactsurface.com",
    "resolved_ips": [
      "203.0.113.19"
    ],
    "ip_class": "dedicated",
    "is_ephemeral": false,
    "monitored": true,
    "interest": "noise",
    "interest_reasons": [],
    "dns_records": {
      "a": [
        "203.0.113.19"
      ]
    },
    "takeover_risk": null,
    "first_seen": "2026-05-13T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  },
  {
    "fingerprint": "d39a42dcf572f16a840e42578bf9a0f3",
    "hostname": "old-shop.demo.exactsurface.com",
    "resolved_ips": [],
    "ip_class": null,
    "is_ephemeral": false,
    "monitored": true,
    "interest": "high",
    "interest_reasons": [],
    "dns_records": {
      "cname": [
        "old-shop.s3.amazonaws.com"
      ]
    },
    "takeover_risk": "Amazon S3",
    "first_seen": "2026-05-14T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "is_new": false,
    "gone": false
  }
] as const;

export const FINDINGS = [
  {
    "fingerprint": "1c582d5bf1b7d3d8e24415a167e4e6a1",
    "check_id": "exposed-git-config",
    "module": "scan",
    "location": "https://legacy.demo.exactsurface.com/.git/config",
    "locator": "",
    "name": "Exposed .git repository",
    "description": "The full source repository is downloadable, including its commit history. Anyone can reconstruct the application source and read any credential ever committed.",
    "severity": "critical",
    "state": "new",
    "is_new": true,
    "reproduction": "curl -sk https://legacy.demo.exactsurface.com/.git/config",
    "references": [],
    "cvss": 9.8,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-11T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "01ecd184cd8fe7112d7eedc3c0803cb0",
    "check_id": "subdomain-takeover-s3",
    "module": "takeover",
    "location": "old-shop.demo.exactsurface.com",
    "locator": "",
    "name": "Subdomain takeover possible: old-shop.demo.exactsurface.com",
    "description": "This name is a dangling CNAME to an Amazon S3 bucket that no longer exists. Anyone can create a bucket with that name and serve content from your domain.",
    "severity": "critical",
    "state": "new",
    "is_new": true,
    "reproduction": "dig +short CNAME old-shop.demo.exactsurface.com",
    "references": [],
    "cvss": 9.8,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-22T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "b74f2ed315d0c80ac4212b24532e8a2f",
    "check_id": "aws-access-key",
    "module": "secrets",
    "location": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js",
    "locator": "",
    "name": "AWS access key exposed in JavaScript",
    "description": "A live-looking AWS key is embedded in a public bundle. Keys in client-side code are readable by every visitor. Shown masked; the raw value is never stored.",
    "severity": "high",
    "state": "new",
    "is_new": true,
    "reproduction": "curl -s https://staging.demo.exactsurface.com/static/js/main.4f2a.js | grep -o 'AKIA[A-Z0-9]*'",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-06T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "8fccf4ffd54a1887efe0537255011b0d",
    "check_id": "cors-reflected-origin",
    "module": "http_misconfig",
    "location": "https://api.demo.exactsurface.com",
    "locator": "",
    "name": "CORS policy accepts an arbitrary origin",
    "description": "The server echoed our arbitrary Origin back in Access-Control-Allow-Origin and set Access-Control-Allow-Credentials: true. Any website a logged-in user visits can read authenticated responses from this host.",
    "severity": "high",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -sI https://api.demo.exactsurface.com -H 'Origin: https://exactsurface-cors-probe.example.com'",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-20T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "cd1ba3345b2be8af97e00421c69a48b2",
    "check_id": "CVE-2024-23897",
    "module": "cve_watch",
    "location": "https://jenkins.demo.exactsurface.com",
    "locator": "",
    "name": "Jenkins CLI arbitrary file read (KEV listed)",
    "description": "The Jenkins version fingerprinted here is affected by CVE-2024-23897, which CISA lists as known-exploited. It allows reading arbitrary files from the controller.",
    "severity": "high",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -s https://jenkins.demo.exactsurface.com/login | grep -i 'jenkins-version'",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-28T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "352df92e7d807bd28968b190e70beae9",
    "check_id": "dmarc-missing",
    "module": "domain_intel",
    "location": "demo.exactsurface.com",
    "locator": "",
    "name": "Domain can be spoofed \u2014 no DMARC policy",
    "description": "No DMARC record is published, so any mail server on the internet can send email that appears to come from this domain and it will not be rejected.",
    "severity": "high",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "dig +short TXT _dmarc.demo.exactsurface.com",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-27T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "fa75e15b37ea02373f283ea9028df300",
    "check_id": "api-surface-graphql",
    "module": "api_surface",
    "location": "https://api.demo.exactsurface.com/graphql",
    "locator": "",
    "name": "GraphQL introspection enabled",
    "description": "One unauthenticated query returns the complete schema \u2014 84 types and the Mutation root. An attacker gets the full API contract, including operations never linked.",
    "severity": "medium",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -s -X POST https://api.demo.exactsurface.com/graphql -d '{\"query\":\"{__schema{types{name}}}\"}'",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-09T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "67b0a03d707cfa7ced0ec569ecef6bbb",
    "check_id": "js-source-map-exposed",
    "module": "js_mine",
    "location": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js",
    "locator": "",
    "name": "Source map published alongside minified JavaScript",
    "description": "A .map file is served next to this bundle. Anyone can download it and reconstruct the original source, including comments and internal file names.",
    "severity": "medium",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -sI https://staging.demo.exactsurface.com/static/js/main.4f2a.js.map",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-27T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "d7a98c6d337d8d6997ac601fc207b98b",
    "check_id": "open-redirect",
    "module": "http_misconfig",
    "location": "https://demo.exactsurface.com/login?next=/dashboard",
    "locator": "",
    "name": "Open redirect via ?next=",
    "description": "Setting ?next= to an external URL made the server respond 302 to it. Anyone can send a link that starts on this trusted domain and lands the victim elsewhere.",
    "severity": "medium",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -sI 'https://demo.exactsurface.com/login?next=https://example.org' | grep -i location",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-25T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "db6539a9a06978852a8ca79daae14eb9",
    "check_id": "dependency-confusion-unclaimed-package",
    "module": "supply_chain",
    "location": "https://demo.exactsurface.com/static/js/vendor.9c1b.js",
    "locator": "",
    "name": "Unclaimed package name referenced in public JS: @demo-internal/auth-client",
    "description": "This package is referenced in your published JavaScript but is not registered on npm. Anyone can publish that exact name and have their code installed in your build.",
    "severity": "medium",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/@demo-internal%2Fauth-client",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-08T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "b62d650bc8460f889009325293fd5b57",
    "check_id": "lookalike-domain-registered",
    "module": "typosquat",
    "location": "dem0-exactsurface.com",
    "locator": "",
    "name": "Lookalike domain registered with mail: dem0-exactsurface.com",
    "description": "This domain is registered and resolving. It was derived from yours by a homoglyph substitution, and it has MX records \u2014 it can send mail that reads as yours.",
    "severity": "medium",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "dig +short dem0-exactsurface.com && dig +short MX dem0-exactsurface.com",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-24T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "5135ea2825ac70d299ee90d750d46851",
    "check_id": "tls-expiring-soon",
    "module": "tls",
    "location": "https://vpn.demo.exactsurface.com",
    "locator": "",
    "name": "TLS certificate expires in 12 days",
    "description": "The certificate for this host expires soon. An expired certificate on a VPN portal trains users to click through browser warnings.",
    "severity": "low",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "echo | openssl s_client -connect vpn.demo.exactsurface.com:443 2>/dev/null | openssl x509 -noout -dates",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-28T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "18788147ecf979eb45d2b0099498d1cc",
    "check_id": "robots-discloses-sensitive-paths",
    "module": "api_surface",
    "location": "https://demo.exactsurface.com/robots.txt",
    "locator": "",
    "name": "robots.txt lists 3 sensitive path(s)",
    "description": "robots.txt asks search engines not to index these paths, which tells anyone who reads the file exactly where they are.\\n\\n  /admin/\\n  /internal/\\n  /backup/",
    "severity": "low",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -s https://demo.exactsurface.com/robots.txt",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-03T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "f4e9d265c28adb398c57830fcb5ac1e6",
    "check_id": "broken-link-unregistered-domain",
    "module": "broken_links",
    "location": "https://blog.demo.exactsurface.com/partners",
    "locator": "",
    "name": "Broken link hijack: old-partner-site.com is unregistered",
    "description": "This page links to a domain that no longer resolves. An attacker can register it and serve content that inherits your page's trust.",
    "severity": "low",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "dig +short old-partner-site.com",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-06-29T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  },
  {
    "fingerprint": "31833c23a11414cbe22ce58f9a0293e3",
    "check_id": "security-txt-present",
    "module": "domain_intel",
    "location": "https://demo.exactsurface.com/.well-known/security.txt",
    "locator": "",
    "name": "security.txt is published",
    "description": "Researchers have a documented way to report issues. This is good practice and is recorded for completeness.",
    "severity": "info",
    "state": "confirmed",
    "is_new": false,
    "reproduction": "curl -s https://demo.exactsurface.com/.well-known/security.txt",
    "references": [],
    "cvss": null,
    "raw": {
      "demo": true
    },
    "first_seen": "2026-07-18T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false
  }
] as const;

export const ENDPOINTS = [
  {
    "fingerprint": "07b105210de9fe1dc57018f2265202fb",
    "url": "https://api.demo.exactsurface.com/api/internal/v2/users",
    "method": "GET",
    "status_code": 401,
    "title": null,
    "tech": [],
    "source": "js",
    "risk_tags": [
      "api",
      "internal"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": true
  },
  {
    "fingerprint": "45a0bd9e4f854c3b2cbbf94bb3c07b88",
    "url": "https://api.demo.exactsurface.com/api/internal/v2/billing",
    "method": "GET",
    "status_code": 401,
    "title": null,
    "tech": [],
    "source": "js",
    "risk_tags": [
      "api",
      "internal",
      "payment"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": true
  },
  {
    "fingerprint": "d4948e2fbafe84a8db9a7c2fabec605f",
    "url": "https://api.demo.exactsurface.com/graphql",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "api_surface",
    "risk_tags": [
      "api",
      "graphql"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "e523777b3343ca5ab0b4b84dd04f2d12",
    "url": "https://api.demo.exactsurface.com/openapi.json",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "api_surface",
    "risk_tags": [
      "api",
      "api-docs"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "dbd9e2014a3be1fee2c542b8a877a8e7",
    "url": "https://admin.demo.exactsurface.com/admin/",
    "method": "GET",
    "status_code": 403,
    "title": "Forbidden",
    "tech": [],
    "source": "feroxbuster",
    "risk_tags": [
      "admin",
      "auth"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": true,
    "bypass_checked_at": "2026-08-01T05:07:11.286146+00:00",
    "bypasses": [
      {
        "technique": "header",
        "label": "X-Original-URL: /admin/",
        "method": "GET",
        "url": "https://admin.demo.exactsurface.com/admin/",
        "request_headers": {
          "X-Original-URL": "/admin/"
        },
        "status": 200,
        "length": 4821,
        "confidence": "high",
        "evidence": "403 \u2192 200 with a 4821-byte body containing 'User administration'",
        "curl": "curl -sk 'https://admin.demo.exactsurface.com/admin/' -H 'X-Original-URL: /admin/'"
      }
    ]
  },
  {
    "fingerprint": "aa81e5e5a0b648481c83eae7daa62a70",
    "url": "https://admin.demo.exactsurface.com/admin/users",
    "method": "GET",
    "status_code": 403,
    "title": "Forbidden",
    "tech": [],
    "source": "feroxbuster",
    "risk_tags": [
      "admin"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": true
  },
  {
    "fingerprint": "5880ecdd4171aa837fefe3d2ad80e3c8",
    "url": "https://legacy.demo.exactsurface.com/.git/config",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "feroxbuster",
    "risk_tags": [
      "exposure"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "5a3e1167619ab347bc546670d649e9f5",
    "url": "https://legacy.demo.exactsurface.com/backup.zip",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "feroxbuster",
    "risk_tags": [
      "exposure"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "91fa95b884a3d23f1fd83b510228c06b",
    "url": "https://demo.exactsurface.com/",
    "method": "GET",
    "status_code": 200,
    "title": "ExactSurface Demo \u2014 Home",
    "tech": [],
    "source": "probe",
    "risk_tags": [],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "90860080a009634871f1873d12174eaf",
    "url": "https://demo.exactsurface.com/login",
    "method": "GET",
    "status_code": 200,
    "title": "Sign in",
    "tech": [],
    "source": "crawl",
    "risk_tags": [
      "auth"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "3bbb30df8979d3408a43b8021f6670b6",
    "url": "https://demo.exactsurface.com/robots.txt",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "api_surface",
    "risk_tags": [],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "5553dabe870e7175770184a59e79af68",
    "url": "https://staging.demo.exactsurface.com/",
    "method": "GET",
    "status_code": 200,
    "title": "Staging \u2014 Demo",
    "tech": [],
    "source": "probe",
    "risk_tags": [],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "2ad80162256541fdb678bd16cbf1a7ec",
    "url": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js",
    "method": "GET",
    "status_code": 200,
    "title": null,
    "tech": [],
    "source": "crawl",
    "risk_tags": [],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "44e40b26b6a0adfdd36a366dbdd14b0f",
    "url": "https://blog.demo.exactsurface.com/wp-admin/",
    "method": "GET",
    "status_code": 302,
    "title": null,
    "tech": [],
    "source": "feroxbuster",
    "risk_tags": [
      "admin",
      "auth"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  },
  {
    "fingerprint": "8f85a097e3743deba62ea961fbefb8ec",
    "url": "https://jenkins.demo.exactsurface.com/login",
    "method": "GET",
    "status_code": 200,
    "title": "Jenkins",
    "tech": [],
    "source": "probe",
    "risk_tags": [
      "auth",
      "admin"
    ],
    "first_seen": "2026-07-02T08:07:11.286146+00:00",
    "last_seen": "2026-08-01T06:07:11.286146+00:00",
    "gone": false,
    "bypass_attempted": false
  }
] as const;

export const SCAN_RUNS = [
  {
    "scan_id": "demo-full-1",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-31T07:27:57.295148+00:00",
    "finished_at": "2026-07-31T08:07:57.295148+00:00",
    "updated_at": "2026-07-31T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-2",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-30T07:27:57.295148+00:00",
    "finished_at": "2026-07-30T08:07:57.295148+00:00",
    "updated_at": "2026-07-30T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-3",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-29T07:27:57.295148+00:00",
    "finished_at": "2026-07-29T08:07:57.295148+00:00",
    "updated_at": "2026-07-29T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-4",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-28T07:27:57.295148+00:00",
    "finished_at": "2026-07-28T08:07:57.295148+00:00",
    "updated_at": "2026-07-28T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-5",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-27T07:27:57.295148+00:00",
    "finished_at": "2026-07-27T08:07:57.295148+00:00",
    "updated_at": "2026-07-27T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-6",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-26T07:27:57.295148+00:00",
    "finished_at": "2026-07-26T08:07:57.295148+00:00",
    "updated_at": "2026-07-26T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-7",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-25T07:27:57.295148+00:00",
    "finished_at": "2026-07-25T08:07:57.295148+00:00",
    "updated_at": "2026-07-25T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-live",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "running",
    "started_at": "2026-08-01T08:01:57.295148+00:00",
    "updated_at": "2026-08-01T08:07:37.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": "not enabled \u2014 needs a Shodan/Censys API key"
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": "not enabled \u2014 needs a Shodan/Censys API key"
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "scan",
        "status": "running",
        "stats": {},
        "note": null
      },
      {
        "name": "secrets",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "cve_watch",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "github_osint",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "cloud_buckets",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "nuclei_watch",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "dork",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "supply_chain",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "typosquat",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "correlate",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "notify",
        "status": "queued",
        "stats": {},
        "note": null
      }
    ],
    "stats": {},
    "targets": [],
    "logs": [
      "scan started for demo.exactsurface.com (28 stages)",
      "stage domain_intel started (limit 180s)",
      "domain_intel demo.exactsurface.com: spoofable=True expires_in=284d \u2192 2 finding(s), 1 new",
      "stage ingest started (limit 300s)",
      "discovering subdomains of demo.exactsurface.com (subfinder + crt.sh)",
      "found 47 candidate(s) (31 subfinder, 16 crt.sh); resolving with dnsx",
      "alterx generated 312 permutation candidate(s) to resolve",
      "alterx: 2/312 permutation(s) actually resolve \u2014 keeping only DNS-confirmed names",
      "dnsx resolved 12/14 in-scope host(s) to live IPs",
      "ingest complete: 47 candidates \u2192 12 in-scope assets, 3 new",
      "stage probe started (limit 300s)",
      "httpx: 12 host(s) probed \u2192 10 alive",
      "probe: staging.demo.exactsurface.com flagged CRITICAL (exposed staging environment)",
      "stage crawl started (limit 600s)",
      "katana: 1284 URL(s) from 10 host(s); gau added 412 archived",
      "stage js_mine started (limit 600s)",
      "js_mine: main.4f2a.js \u2192 218 item(s), 34 interesting, 6 host(s)",
      "js_mine: source map found at main.4f2a.js.map",
      "stage api_surface started (limit 900s)",
      "api_surface: api.demo.exactsurface.com/robots.txt \u2192 3 path(s)",
      "api_surface: API schema at https://api.demo.exactsurface.com/openapi.json",
      "api_surface: GraphQL at https://api.demo.exactsurface.com/graphql (medium)",
      "stage http_misconfig started (limit 600s)",
      "http_misconfig: CORS https://api.demo.exactsurface.com \u2192 allow-origin reflected, credentials=True",
      "http_misconfig: open redirect via ?next= on https://demo.exactsurface.com/login",
      "http_misconfig: 4 host(s) behind Cloudflare, 6 without",
      "stage scan started (limit 3600s)",
      "nuclei: 1 critical, 2 high, 4 medium across 10 host(s)",
      "stage secrets started (limit 600s)",
      "secrets: AWS key found in staging.demo.exactsurface.com/static/js/main.4f2a.js (masked)",
      "stage correlate started (limit 120s)",
      "correlate: 3 host(s) with 2+ signals \u2192 1 attack path"
    ]
  }
] as const;

export const SCAN_LOGS = [
  "scan started for demo.exactsurface.com (28 stages)",
  "stage domain_intel started (limit 180s)",
  "domain_intel demo.exactsurface.com: spoofable=True expires_in=284d \u2192 2 finding(s), 1 new",
  "stage ingest started (limit 300s)",
  "discovering subdomains of demo.exactsurface.com (subfinder + crt.sh)",
  "found 47 candidate(s) (31 subfinder, 16 crt.sh); resolving with dnsx",
  "alterx generated 312 permutation candidate(s) to resolve",
  "alterx: 2/312 permutation(s) actually resolve \u2014 keeping only DNS-confirmed names",
  "dnsx resolved 12/14 in-scope host(s) to live IPs",
  "ingest complete: 47 candidates \u2192 12 in-scope assets, 3 new",
  "stage probe started (limit 300s)",
  "httpx: 12 host(s) probed \u2192 10 alive",
  "probe: staging.demo.exactsurface.com flagged CRITICAL (exposed staging environment)",
  "stage crawl started (limit 600s)",
  "katana: 1284 URL(s) from 10 host(s); gau added 412 archived",
  "stage js_mine started (limit 600s)",
  "js_mine: main.4f2a.js \u2192 218 item(s), 34 interesting, 6 host(s)",
  "js_mine: source map found at main.4f2a.js.map",
  "stage api_surface started (limit 900s)",
  "api_surface: api.demo.exactsurface.com/robots.txt \u2192 3 path(s)",
  "api_surface: API schema at https://api.demo.exactsurface.com/openapi.json",
  "api_surface: GraphQL at https://api.demo.exactsurface.com/graphql (medium)",
  "stage http_misconfig started (limit 600s)",
  "http_misconfig: CORS https://api.demo.exactsurface.com \u2192 allow-origin reflected, credentials=True",
  "http_misconfig: open redirect via ?next= on https://demo.exactsurface.com/login",
  "http_misconfig: 4 host(s) behind Cloudflare, 6 without",
  "stage scan started (limit 3600s)",
  "nuclei: 1 critical, 2 high, 4 medium across 10 host(s)",
  "stage secrets started (limit 600s)",
  "secrets: AWS key found in staging.demo.exactsurface.com/static/js/main.4f2a.js (masked)",
  "stage correlate started (limit 120s)",
  "correlate: 3 host(s) with 2+ signals \u2192 1 attack path"
] as const;

export const STAGE_NAMES = [
  "domain_intel",
  "ingest",
  "cloud_assets",
  "uncover",
  "reverse_dns",
  "probe",
  "tls",
  "takeover",
  "crawl",
  "content_discovery",
  "js_mine",
  "api_surface",
  "http_misconfig",
  "param_discovery",
  "broken_links",
  "port_scan",
  "service_scan",
  "scan",
  "secrets",
  "cve_watch",
  "github_osint",
  "cloud_buckets",
  "nuclei_watch",
  "dork",
  "supply_chain",
  "typosquat",
  "correlate",
  "notify"
] as const;

export const PORTS = [
  {
    "fingerprint": "p1",
    "ip": "203.0.113.14",
    "port": 8080,
    "protocol": "tcp",
    "service": "http",
    "product": "Jetty",
    "version": "9.4.51",
    "first_seen": "2026-07-12T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00",
    "gone": false
  },
  {
    "fingerprint": "p2",
    "ip": "203.0.113.14",
    "port": 50000,
    "protocol": "tcp",
    "service": "jenkins-cli",
    "product": "Jenkins",
    "version": "2.426",
    "first_seen": "2026-07-12T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00",
    "gone": false
  },
  {
    "fingerprint": "p3",
    "ip": "203.0.113.18",
    "port": 3389,
    "protocol": "tcp",
    "service": "ms-wbt-server",
    "product": "Microsoft Terminal Services",
    "version": "",
    "first_seen": "2026-07-12T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00",
    "gone": false
  },
  {
    "fingerprint": "p4",
    "ip": "203.0.113.11",
    "port": 443,
    "protocol": "tcp",
    "service": "https",
    "product": "nginx",
    "version": "1.24.0",
    "first_seen": "2026-07-12T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00",
    "gone": false
  }
] as const;

export const SECRETS = [
  {
    "fingerprint": "s1",
    "kind": "aws_key",
    "masked": "AKIA\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u20227Q3M",
    "location": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js",
    "severity": "high",
    "first_seen": "2026-07-28T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00",
    "is_new": true
  }
] as const;

export const LEAKS = [
  {
    "fingerprint": "l1",
    "kind": "generic_api_key",
    "masked": "sk_live_\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u20224b2f",
    "source": "github",
    "repo": "demo-corp/internal-scripts",
    "url": "https://github.com/demo-corp/internal-scripts",
    "severity": "high",
    "first_seen": "2026-07-23T08:07:57.295148+00:00"
  }
] as const;

export const CVES = [
  {
    "fingerprint": "c1",
    "cve_id": "CVE-2024-23897",
    "asset": "jenkins.demo.exactsurface.com",
    "cpe": "cpe:2.3:a:jenkins:jenkins",
    "severity": "high",
    "cvss": 9.8,
    "kev": true,
    "confidence": "high",
    "summary": "Jenkins CLI allows arbitrary file read on the controller.",
    "first_seen": "2026-07-21T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00"
  }
] as const;

export const DELTAS = [
  {
    "fingerprint": "d1",
    "kind": "asset_added",
    "target": "staging.demo.exactsurface.com",
    "summary": "New subdomain appeared",
    "severity": "high",
    "created_at": "2026-08-01T03:07:57.295148+00:00"
  },
  {
    "fingerprint": "d2",
    "kind": "finding_added",
    "target": "legacy.demo.exactsurface.com",
    "summary": "New critical finding: exposed .git",
    "severity": "critical",
    "created_at": "2026-07-31T22:07:57.295148+00:00"
  },
  {
    "fingerprint": "d3",
    "kind": "endpoint_added",
    "target": "api.demo.exactsurface.com/graphql",
    "summary": "GraphQL endpoint discovered",
    "severity": "medium",
    "created_at": "2026-07-31T17:07:57.295148+00:00"
  },
  {
    "fingerprint": "d4",
    "kind": "asset_removed",
    "target": "temp-cdn.demo.exactsurface.com",
    "summary": "Host no longer resolves",
    "severity": "info",
    "created_at": "2026-07-31T12:07:57.295148+00:00"
  },
  {
    "fingerprint": "d5",
    "kind": "port_opened",
    "target": "203.0.113.14:50000",
    "summary": "Jenkins CLI port opened",
    "severity": "high",
    "created_at": "2026-07-31T07:07:57.295148+00:00"
  }
] as const;

export const JS_FILES = [
  {
    "fingerprint": "j1",
    "url": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js",
    "size": 482193,
    "interesting_count": 34,
    "source_map": "https://staging.demo.exactsurface.com/static/js/main.4f2a.js.map",
    "hostnames": [
      "api.demo.exactsurface.com",
      "internal-metrics.demo.exactsurface.com"
    ],
    "items": [
      {
        "value": "/api/internal/v2/users",
        "kind": "path",
        "tags": [
          "api",
          "internal"
        ],
        "absolute": "https://api.demo.exactsurface.com/api/internal/v2/users"
      },
      {
        "value": "/api/internal/v2/billing",
        "kind": "path",
        "tags": [
          "api",
          "internal",
          "payment"
        ],
        "absolute": "https://api.demo.exactsurface.com/api/internal/v2/billing"
      },
      {
        "value": "/admin/users",
        "kind": "path",
        "tags": [
          "admin"
        ],
        "absolute": "https://api.demo.exactsurface.com/admin/users"
      },
      {
        "value": "internal-metrics.demo.exactsurface.com",
        "kind": "url",
        "tags": [
          "own-domain"
        ],
        "absolute": null
      }
    ],
    "first_seen": "2026-07-26T08:07:57.295148+00:00",
    "last_seen": "2026-08-01T06:07:57.295148+00:00"
  }
] as const;

export const DOMAIN_INTEL = {
  "email": {
    "spf": "v=spf1 include:_spf.google.com ~all",
    "spf_present": true,
    "dmarc": null,
    "dmarc_present": false,
    "dmarc_policy": null,
    "dkim_selectors": [
      "google"
    ],
    "spoofable": true
  },
  "registration": {
    "registrar": "Example Registrar, Inc.",
    "created_at": "2022-03-15T08:07:57.295148+00:00",
    "expires_at": "2027-05-12T08:07:57.295148+00:00",
    "days_to_expiry": 284,
    "statuses": [
      "clientTransferProhibited"
    ],
    "nameservers": [
      "ns1.example-dns.com",
      "ns2.example-dns.com"
    ],
    "dnssec": false,
    "transfer_locked": true
  },
  "checked_at": "2026-08-01T06:07:57.295148+00:00"
} as const;

export const STATS = {
  "programs": 1,
  "assets": 12,
  "endpoints": 15,
  "secrets": 1,
  "findings": 15,
  "new_findings": 3,
  "findings_by_severity": {
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 3,
    "info": 1
  },
  "open_actionable": 11,
  "informational": 1,
  "findings_by_state": {
    "new": 3,
    "confirmed": 12
  },
  "false_positive_rate": 0.0,
  "false_positives": 0,
  "decided": 12
} as const;

export const PROGRAMS = [
  {
    "program_id": "prog_demo",
    "apex_domain": "demo.exactsurface.com",
    "verified": true,
    "enabled": true,
    "scan_shared_infra": false,
    "enabled_modules": [
      "tls",
      "param_discovery",
      "typosquat"
    ],
    "verification_method": "dns_txt",
    "created_at": "2026-05-03T08:07:57.295148+00:00"
  }
] as const;

export const ACTIVITY = [
  {
    "scan_id": "demo-full-live",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "running",
    "started_at": "2026-08-01T08:01:57.295148+00:00",
    "updated_at": "2026-08-01T08:07:37.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": "not enabled \u2014 needs a Shodan/Censys API key"
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": "not enabled \u2014 needs a Shodan/Censys API key"
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 9
        },
        "note": null
      },
      {
        "name": "scan",
        "status": "running",
        "stats": {},
        "note": null
      },
      {
        "name": "secrets",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "cve_watch",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "github_osint",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "cloud_buckets",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "nuclei_watch",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "dork",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "supply_chain",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "typosquat",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "correlate",
        "status": "queued",
        "stats": {},
        "note": null
      },
      {
        "name": "notify",
        "status": "queued",
        "stats": {},
        "note": null
      }
    ],
    "stats": {},
    "targets": [],
    "logs": [
      "scan started for demo.exactsurface.com (28 stages)",
      "stage domain_intel started (limit 180s)",
      "domain_intel demo.exactsurface.com: spoofable=True expires_in=284d \u2192 2 finding(s), 1 new",
      "stage ingest started (limit 300s)",
      "discovering subdomains of demo.exactsurface.com (subfinder + crt.sh)",
      "found 47 candidate(s) (31 subfinder, 16 crt.sh); resolving with dnsx",
      "alterx generated 312 permutation candidate(s) to resolve",
      "alterx: 2/312 permutation(s) actually resolve \u2014 keeping only DNS-confirmed names",
      "dnsx resolved 12/14 in-scope host(s) to live IPs",
      "ingest complete: 47 candidates \u2192 12 in-scope assets, 3 new",
      "stage probe started (limit 300s)",
      "httpx: 12 host(s) probed \u2192 10 alive",
      "probe: staging.demo.exactsurface.com flagged CRITICAL (exposed staging environment)",
      "stage crawl started (limit 600s)",
      "katana: 1284 URL(s) from 10 host(s); gau added 412 archived",
      "stage js_mine started (limit 600s)",
      "js_mine: main.4f2a.js \u2192 218 item(s), 34 interesting, 6 host(s)",
      "js_mine: source map found at main.4f2a.js.map",
      "stage api_surface started (limit 900s)",
      "api_surface: api.demo.exactsurface.com/robots.txt \u2192 3 path(s)",
      "api_surface: API schema at https://api.demo.exactsurface.com/openapi.json",
      "api_surface: GraphQL at https://api.demo.exactsurface.com/graphql (medium)",
      "stage http_misconfig started (limit 600s)",
      "http_misconfig: CORS https://api.demo.exactsurface.com \u2192 allow-origin reflected, credentials=True",
      "http_misconfig: open redirect via ?next= on https://demo.exactsurface.com/login",
      "http_misconfig: 4 host(s) behind Cloudflare, 6 without",
      "stage scan started (limit 3600s)",
      "nuclei: 1 critical, 2 high, 4 medium across 10 host(s)",
      "stage secrets started (limit 600s)",
      "secrets: AWS key found in staging.demo.exactsurface.com/static/js/main.4f2a.js (masked)",
      "stage correlate started (limit 120s)",
      "correlate: 3 host(s) with 2+ signals \u2192 1 attack path"
    ]
  },
  {
    "scan_id": "demo-full-7",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-25T07:27:57.295148+00:00",
    "finished_at": "2026-07-25T08:07:57.295148+00:00",
    "updated_at": "2026-07-25T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-6",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-26T07:27:57.295148+00:00",
    "finished_at": "2026-07-26T08:07:57.295148+00:00",
    "updated_at": "2026-07-26T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-5",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-27T07:27:57.295148+00:00",
    "finished_at": "2026-07-27T08:07:57.295148+00:00",
    "updated_at": "2026-07-27T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-4",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-28T07:27:57.295148+00:00",
    "finished_at": "2026-07-28T08:07:57.295148+00:00",
    "updated_at": "2026-07-28T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-3",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-29T07:27:57.295148+00:00",
    "finished_at": "2026-07-29T08:07:57.295148+00:00",
    "updated_at": "2026-07-29T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-2",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-30T07:27:57.295148+00:00",
    "finished_at": "2026-07-30T08:07:57.295148+00:00",
    "updated_at": "2026-07-30T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  },
  {
    "scan_id": "demo-full-1",
    "program_id": "prog_demo",
    "pipeline": "full",
    "status": "success",
    "started_at": "2026-07-31T07:27:57.295148+00:00",
    "finished_at": "2026-07-31T08:07:57.295148+00:00",
    "updated_at": "2026-07-31T08:07:57.295148+00:00",
    "stages": [
      {
        "name": "domain_intel",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "ingest",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_assets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "uncover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "reverse_dns",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "probe",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "tls",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "takeover",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "crawl",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "content_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "js_mine",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "api_surface",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "http_misconfig",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "param_discovery",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "broken_links",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "port_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "service_scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "scan",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "secrets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cve_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "github_osint",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "cloud_buckets",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "nuclei_watch",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "dork",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "supply_chain",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "typosquat",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "correlate",
        "status": "success",
        "stats": {
          "found": 7
        }
      },
      {
        "name": "notify",
        "status": "success",
        "stats": {
          "found": 7
        }
      }
    ],
    "stats": {
      "assets": 12,
      "findings": 15
    },
    "targets": []
  }
] as const;

export const ME = {
  "user_id": "u_demo",
  "email": "demo@exactsurface.com",
  "role": "owner",
  "tenant_id": "t_demo",
  "email_verified": true,
  "plan": "business",
  "permissions": [
    "*"
  ]
} as const;

export const LOGIN = {
  "access_token": "demo-token",
  "tenant_id": "t_demo"
} as const;

export const LICENSE = {
  "status": "active",
  "read_only": false,
  "plan": "business",
  "customer_name": "Demo Corp",
  "expires_at": null,
  "reason": "",
  "days_left": null
} as const;

export const MEMBERS = [
  {
    "user_id": "u_demo",
    "email": "demo@exactsurface.com",
    "role": "owner",
    "group_ids": [],
    "email_verified": true,
    "created_at": "2026-05-03T08:07:57.295148+00:00"
  },
  {
    "user_id": "u_analyst",
    "email": "analyst@demo-corp.example",
    "role": "member",
    "group_ids": [
      "g_viewer"
    ],
    "email_verified": true,
    "created_at": "2026-05-03T08:07:57.295148+00:00"
  }
] as const;

export const GROUPS = [
  {
    "group_id": "g_viewer",
    "name": "Viewers",
    "permissions": [
      "view"
    ]
  },
  {
    "group_id": "g_ops",
    "name": "Security ops",
    "permissions": [
      "view",
      "programs.manage"
    ]
  }
] as const;

export const PERMISSIONS = [
  {
    "key": "view",
    "label": "View everything"
  },
  {
    "key": "programs.manage",
    "label": "Manage domains and scans"
  },
  {
    "key": "settings.manage",
    "label": "Manage settings and integrations"
  },
  {
    "key": "members.manage",
    "label": "Manage members (owner only)"
  }
] as const;

export const CHANNELS = [
  {
    "channel_id": "ch1",
    "kind": "slack",
    "target": "#security-alerts",
    "enabled": true,
    "min_severity": "high"
  }
] as const;

export const INTEGRATIONS = [
  {
    "name": "slack",
    "configured": true
  },
  {
    "name": "jira",
    "configured": false
  },
  {
    "name": "webhook",
    "configured": false
  }
] as const;

export const AUTHORIZATION = {
  "program_id": "prog_demo",
  "authorized_by": "u_demo",
  "apex_verified": true,
  "verification_method": "dns_txt",
  "ip_scope": [],
  "revoked": false,
  "authorized_at": "2026-05-03T08:07:57.295148+00:00",
  "tos_version": "v1"
} as const;

export const ATTACK_PATHS = {
  "count": 1,
  "paths": [
    {
      "host": "staging.demo.exactsurface.com",
      "headline": "staging.demo.exactsurface.com: an exposed staging environment leads to an admin panel",
      "summary": "On staging.demo.exactsurface.com, an attacker starting with nothing but your domain finds internal API routes named in the public JavaScript \u2192 a live credential left in a public response \u2192 an access-control check that can be walked around. Each step below links to the finding it came from.",
      "severity": "high",
      "risk_score": 70,
      "steps": [
        {
          "phase": "foothold",
          "text": "internal API routes named in the public JavaScript",
          "finding_id": "67b0a03d707cfa7ced0ec569ecef6bbb",
          "check_id": "js-source-map-exposed",
          "severity": "medium"
        },
        {
          "phase": "credentials",
          "text": "a live credential left in a public response",
          "finding_id": "b74f2ed315d0c80ac4212b24532e8a2f",
          "check_id": "aws-access-key",
          "severity": "high"
        },
        {
          "phase": "access",
          "text": "a CORS policy that hands data to any origin",
          "finding_id": "8fccf4ffd54a1887efe0537255011b0d",
          "check_id": "cors-reflected-origin",
          "severity": "high"
        }
      ]
    }
  ]
} as const;

export const CORRELATION = {
  "count": 3,
  "chains": 1,
  "issues": [
    {
      "host": "staging.demo.exactsurface.com",
      "risk_score": 70,
      "highest_severity": "high",
      "is_chain": true,
      "signals": [
        "exposed staging environment",
        "leaked AWS key in JS",
        "source map published"
      ]
    },
    {
      "host": "jenkins.demo.exactsurface.com",
      "risk_score": 55,
      "highest_severity": "high",
      "is_chain": true,
      "signals": [
        "KEV-listed CVE-2024-23897",
        "Jenkins CLI port 50000 open"
      ]
    },
    {
      "host": "legacy.demo.exactsurface.com",
      "risk_score": 40,
      "highest_severity": "critical",
      "is_chain": false,
      "signals": [
        "exposed .git repository"
      ]
    }
  ]
} as const;

export const ATTACK_SURFACE = {
  "generated_at": "2026-08-02T16:03:52.000Z",
  "latest_scan_at": "2026-08-02T16:03:52.000Z",
  "previous_scan_at": "2026-08-01T16:01:17.000Z",
  "scan_count": 7,
  "current": {
    "total": 56,
    "assets": { "total": 12 },
    "endpoints": { "total": 15 },
    "ports": { "total": 10, "high": 2, "medium": 5, "low": 3 },
    "findings": { "total": 15, "critical": 3, "high": 5, "medium": 4, "low": 3 },
    "secrets": { "total": 3, "high": 2, "medium": 1 },
    "leaks": { "total": 1, "medium": 1 }
  },
  "change": {
    "opened": 9,
    "resolved": 2,
    "net": 7,
    "assets": { "opened": 2, "resolved": 0 },
    "endpoints": { "opened": 3, "resolved": 1 },
    "ports": { "opened": 1, "resolved": 0 },
    "findings": { "opened": 2, "resolved": 1 },
    "secrets": { "opened": 1, "resolved": 0 },
    "leaks": { "opened": 0, "resolved": 0 }
  },
  "series": [
    { "at": "2026-07-27T16:00:00.000Z", "total": 42, "assets": 9, "endpoints": 11, "ports": 7, "findings": 12, "secrets": 2, "leaks": 1 },
    { "at": "2026-07-29T16:00:00.000Z", "total": 45, "assets": 10, "endpoints": 12, "ports": 8, "findings": 12, "secrets": 2, "leaks": 1 },
    { "at": "2026-07-31T16:00:00.000Z", "total": 49, "assets": 10, "endpoints": 13, "ports": 9, "findings": 14, "secrets": 2, "leaks": 1 },
    { "at": "2026-08-01T16:01:17.000Z", "total": 49, "assets": 10, "endpoints": 13, "ports": 9, "findings": 14, "secrets": 2, "leaks": 1 },
    { "at": "2026-08-02T16:03:52.000Z", "total": 56, "assets": 12, "endpoints": 15, "ports": 10, "findings": 15, "secrets": 3, "leaks": 1 }
  ],
  "recent": [
    { "kind": "opened", "type": "asset", "label": "jenkins.demo.exactsurface.com", "at": "2026-08-02T16:03:52.000Z", "severity": "critical" },
    { "kind": "opened", "type": "endpoint", "label": "https://api.demo.exactsurface.com/graphql", "at": "2026-08-02T16:03:52.000Z", "severity": "medium" },
    { "kind": "opened", "type": "finding", "label": "Exposed .git repository", "at": "2026-08-02T16:03:52.000Z", "severity": "critical" },
    { "kind": "opened", "type": "secret", "label": "AWS access key in public JavaScript", "at": "2026-08-02T16:03:52.000Z", "severity": "high" },
    { "kind": "resolved", "type": "endpoint", "label": "https://old-shop.demo.exactsurface.com/debug", "at": "2026-08-02T16:03:52.000Z", "severity": null },
    { "kind": "resolved", "type": "finding", "label": "Missing security.txt", "at": "2026-08-02T16:03:52.000Z", "severity": "low" }
  ]
} as const;

export const SCHEDULE_DEFAULTS = {
  "cadence_overrides": {},
  "pipelines": []
} as const;

export const TIMEOUT_DEFAULTS = {
  "timeout_overrides": {},
  "stages": []
} as const;

export const ALERT_POLICY_DEFAULTS = {
  alert_policy: {},
  defaults: {
    finding_min_severity: "medium",
    alert_findings: true,
    alert_secrets: true,
    alert_leaks: true,
    alert_cves: true,
    cve_min_cvss: 0,
    alert_new_assets: true,
    alert_new_ports: true,
    port_filter: "",
  },
  severities: ["critical", "high", "medium", "low", "info"],
} as const;

export const ALERT_POLICY = {
  alert_policy: {},
  effective: {
    finding_min_severity: "medium",
    alert_findings: true,
    alert_secrets: true,
    alert_leaks: true,
    alert_cves: true,
    cve_min_cvss: 0,
    alert_new_assets: true,
    alert_new_ports: true,
    port_filter: "",
  },
  defaults: {
    finding_min_severity: "medium",
    alert_findings: true,
    alert_secrets: true,
    alert_leaks: true,
    alert_cves: true,
    cve_min_cvss: 0,
    alert_new_assets: true,
    alert_new_ports: true,
    port_filter: "",
  },
  tenant_defaults: {},
  severities: ["critical", "high", "medium", "low", "info"],
} as const;

export const TIMEOUTS = {
  "program_id": "prog_demo",
  "timeout_overrides": {},
  "stages": [
    {
      "stage": "domain_intel",
      "label": "domain_intel",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "ingest",
      "label": "ingest",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "cloud_assets",
      "label": "cloud_assets",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "uncover",
      "label": "uncover",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "reverse_dns",
      "label": "reverse_dns",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "probe",
      "label": "probe",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "tls",
      "label": "tls",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "takeover",
      "label": "takeover",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "crawl",
      "label": "crawl",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "content_discovery",
      "label": "content_discovery",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "js_mine",
      "label": "js_mine",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "api_surface",
      "label": "api_surface",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "http_misconfig",
      "label": "http_misconfig",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "param_discovery",
      "label": "param_discovery",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "broken_links",
      "label": "broken_links",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "port_scan",
      "label": "port_scan",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "service_scan",
      "label": "service_scan",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "scan",
      "label": "scan",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "secrets",
      "label": "secrets",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "cve_watch",
      "label": "cve_watch",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "github_osint",
      "label": "github_osint",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "cloud_buckets",
      "label": "cloud_buckets",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "nuclei_watch",
      "label": "nuclei_watch",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "dork",
      "label": "dork",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "supply_chain",
      "label": "supply_chain",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "typosquat",
      "label": "typosquat",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "correlate",
      "label": "correlate",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    },
    {
      "stage": "notify",
      "label": "notify",
      "default_seconds": 600,
      "effective_seconds": 600,
      "source": "default"
    }
  ]
} as const;

export const SCHEDULE = {
  "program_id": "prog_demo",
  "initial_scan_completed_at": "2026-05-03T08:07:57.295148+00:00",
  "last_full_run": {
    "scan_id": "demo-full-1",
    "status": "success",
    "started_at": "2026-07-31T07:27:57.295148+00:00",
    "finished_at": "2026-07-31T08:07:57.295148+00:00"
  },
  "phases": [
    {
      "pipeline": "domain_intel",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "ingest",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "cloud_assets",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "uncover",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "reverse_dns",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "probe",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "tls",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "takeover",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "crawl",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "content_discovery",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "js_mine",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "api_surface",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "http_misconfig",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "param_discovery",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "broken_links",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "port_scan",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "service_scan",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "scan",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "secrets",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "cve_watch",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "github_osint",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "cloud_buckets",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "nuclei_watch",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "dork",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "supply_chain",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "typosquat",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    },
    {
      "pipeline": "notify",
      "interval_seconds": 86400,
      "last_run_at": "2026-07-31T08:07:57.295148+00:00",
      "next_due_at": null,
      "source": "default"
    }
  ]
} as const;

export const MODULES = {
  "program_id": "prog_demo",
  "modules": [
    {
      "name": "domain_intel",
      "label": "Domain intelligence",
      "summary": "Domain intelligence \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "ingest",
      "label": "Subdomain discovery",
      "summary": "Subdomain discovery \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": true,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "cloud_assets",
      "label": "Cloud asset inventory",
      "summary": "Cloud asset inventory \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "uncover",
      "label": "Internet-index search",
      "summary": "Internet-index search \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "reverse_dns",
      "label": "Reverse-DNS sweep",
      "summary": "Reverse-DNS sweep \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "probe",
      "label": "Live-host probing",
      "summary": "Live-host probing \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": true,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "tls",
      "label": "TLS inspection",
      "summary": "TLS inspection \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "takeover",
      "label": "Subdomain takeover",
      "summary": "Subdomain takeover \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "crawl",
      "label": "Crawling & archives",
      "summary": "Crawling & archives \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "content_discovery",
      "label": "Content discovery",
      "summary": "Content discovery \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "js_mine",
      "label": "JavaScript mining",
      "summary": "JavaScript mining \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "api_surface",
      "label": "API & path disclosure",
      "summary": "API & path disclosure \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "http_misconfig",
      "label": "CORS, redirects & WAF",
      "summary": "CORS, redirects & WAF \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "param_discovery",
      "label": "Hidden parameters",
      "summary": "Hidden parameters \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "broken_links",
      "label": "Broken-link hijacking",
      "summary": "Broken-link hijacking \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "port_scan",
      "label": "Port scanning",
      "summary": "Port scanning \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "service_scan",
      "label": "Service fingerprinting",
      "summary": "Service fingerprinting \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "scan",
      "label": "Vulnerability scanning",
      "summary": "Vulnerability scanning \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "secrets",
      "label": "Exposed secrets",
      "summary": "Exposed secrets \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "cve_watch",
      "label": "CVE watch",
      "summary": "CVE watch \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "github_osint",
      "label": "Public code leaks",
      "summary": "Public code leaks \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "cloud_buckets",
      "label": "Cloud storage exposure",
      "summary": "Cloud storage exposure \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "nuclei_watch",
      "label": "New-template watch",
      "summary": "New-template watch \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "dork",
      "label": "Search-engine exposure",
      "summary": "Search-engine exposure \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": false,
      "turned_off": false,
      "skip_reason": "not enabled \u2014 needs an API key or extra requests",
      "licensed": true
    },
    {
      "name": "supply_chain",
      "label": "Dependency confusion",
      "summary": "Dependency confusion \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "typosquat",
      "label": "Lookalike domains",
      "summary": "Lookalike domains \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": true,
      "opt_in_reason": "needs an API key or extra requests",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "correlate",
      "label": "Risk correlation",
      "summary": "Risk correlation \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": false,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    },
    {
      "name": "notify",
      "label": "Alerting",
      "summary": "Alerting \u2014 see the Knowledge page for what this checks.",
      "requires": [],
      "required_by": [],
      "essential": false,
      "schedulable": true,
      "opt_in": false,
      "opt_in_reason": "",
      "enabled": true,
      "turned_off": false,
      "skip_reason": "",
      "licensed": true
    }
  ]
} as const;


/** The real Playground catalogue, generated from `core/playground.py` so the demo's
 *  palette is identical to the product's. Regenerate with:
 *  `python -c "import json,core.playground as p; print(json.dumps(p.as_json(),indent=2))"`
 */
export const PLAYGROUND_NODES = [
  {
    "key": "pipeline:domain_intel",
    "tier": "pipeline",
    "label": "Domain intelligence",
    "summary": "Email spoofability (SPF/DMARC/DKIM) and domain registration risk. Fully passive \u2014 reads DNS and the public registry, never touches your servers.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "domain_intel",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:ingest",
    "tier": "pipeline",
    "label": "Subdomain discovery",
    "summary": "Finds your subdomains and resolves them. Everything else works from this list.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "ingest",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:cloud_assets",
    "tier": "pipeline",
    "label": "Cloud asset inventory",
    "summary": "Asks your own AWS/GCP/Azure/DigitalOcean accounts what they are running, so you find the load balancer or VM nobody pointed a DNS name at. Credentials stay in your deployment and are never sent anywhere.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "cloud_assets",
    "impl": "",
    "caution": "set up by whoever deployed this instance, not from Settings \u2014 see CLIENT_GUIDE.md \u00a75.9 (EXACTSURFACE_CLOUDLIST_CONFIG)"
  },
  {
    "key": "pipeline:uncover",
    "tier": "pipeline",
    "label": "Internet-index search",
    "summary": "Looks your assets up in Shodan/Censys/Fofa to find hosts DNS never reveals.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "uncover",
    "impl": "",
    "caution": "needs a Shodan/Censys API key"
  },
  {
    "key": "pipeline:reverse_dns",
    "tier": "pipeline",
    "label": "Reverse-DNS sweep",
    "summary": "PTR-sweeps the IP ranges confirmed to be yours, finding hosts that exist in IP space but were never published in DNS. Only runs on ASN-verified ranges.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "reverse_dns",
    "impl": "",
    "caution": "needs ASN-confirmed dedicated IP ranges; sweeps up to 8192 addresses"
  },
  {
    "key": "pipeline:probe",
    "tier": "pipeline",
    "label": "Live-host probing",
    "summary": "Checks which hosts answer over HTTP/S and fingerprints their technology.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "probe",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:tls",
    "tier": "pipeline",
    "label": "TLS inspection",
    "summary": "Certificate expiry and weak TLS configuration.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "tls",
    "impl": "",
    "caution": "adds a TLS handshake per host"
  },
  {
    "key": "pipeline:takeover",
    "tier": "pipeline",
    "label": "Subdomain takeover",
    "summary": "Dangling DNS records pointing at cloud services somebody else could claim.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "takeover",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:crawl",
    "tier": "pipeline",
    "label": "Crawling & archives",
    "summary": "Crawls your live sites and mines Wayback/CommonCrawl history for URLs.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      },
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "crawl",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:content_discovery",
    "tier": "pipeline",
    "label": "Content discovery",
    "summary": "Brute-forces hidden paths and files with tech-aware wordlists.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "content_discovery",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:js_mine",
    "tier": "pipeline",
    "label": "JavaScript mining",
    "summary": "Reads your own JS bundles for API routes, internal hostnames and source maps \u2014 the routes the app tells every visitor about.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "js_mine",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:api_surface",
    "tier": "pipeline",
    "label": "API & path disclosure",
    "summary": "Reads robots.txt, sitemaps, API schemas (Swagger/OpenAPI), GraphQL introspection and .well-known \u2014 the surface each host advertises about itself.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "api_surface",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:http_misconfig",
    "tier": "pipeline",
    "label": "CORS, redirects & WAF",
    "summary": "Checks whether hosts hand data to any origin (CORS), can launder a phishing link (open redirect), and which of them sit behind a WAF.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "http_misconfig",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:param_discovery",
    "tier": "pipeline",
    "label": "Hidden parameters",
    "summary": "Inventories the query parameters your pages already use, and probes for undocumented ones that change how the application behaves.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "param_discovery",
    "impl": "",
    "caution": "sends extra requests per URL to compare responses"
  },
  {
    "key": "pipeline:broken_links",
    "tier": "pipeline",
    "label": "Broken-link hijacking",
    "summary": "Outbound links whose destination is an unregistered domain or an unclaimed social handle that an attacker could take over.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "broken_links",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:port_scan",
    "tier": "pipeline",
    "label": "Port scanning",
    "summary": "Open ports on infrastructure you have confirmed as yours.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "port_scan",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:service_scan",
    "tier": "pipeline",
    "label": "Service fingerprinting",
    "summary": "Identifies the software and version behind each open port.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "service_scan",
    "impl": "",
    "caution": "slower, deeper probing of each open port"
  },
  {
    "key": "pipeline:scan",
    "tier": "pipeline",
    "label": "Vulnerability scanning",
    "summary": "Runs the Nuclei template corpus against your live endpoints.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "scan",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:secrets",
    "tier": "pipeline",
    "label": "Exposed secrets",
    "summary": "Scans page and script bodies for leaked API keys, tokens and credentials.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "secrets",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:cve_watch",
    "tier": "pipeline",
    "label": "CVE watch",
    "summary": "Matches known (and actively exploited) CVEs to your fingerprinted software.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "cve_watch",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:github_osint",
    "tier": "pipeline",
    "label": "Public code leaks",
    "summary": "Searches public repositories for secrets tied to your domain.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "github_osint",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:cloud_buckets",
    "tier": "pipeline",
    "label": "Cloud storage exposure",
    "summary": "Guesses and checks S3/GCS/Azure bucket names derived from your domain.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "cloud_buckets",
    "impl": "",
    "caution": "probes ~45 third-party endpoints; name-derived attribution"
  },
  {
    "key": "pipeline:nuclei_watch",
    "tier": "pipeline",
    "label": "New-template watch",
    "summary": "Alerts when a newly published Nuclei template starts matching your stack.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "nuclei_watch",
    "impl": "",
    "caution": "baselines the template set on first run"
  },
  {
    "key": "pipeline:dork",
    "tier": "pipeline",
    "label": "Search-engine exposure",
    "summary": "Finds content of yours that search engines have indexed but shouldn't have.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "dork",
    "impl": "",
    "caution": "needs a search API key (SerpAPI/Brave/Google CSE)"
  },
  {
    "key": "pipeline:supply_chain",
    "tier": "pipeline",
    "label": "Dependency confusion",
    "summary": "Internal package names referenced in your public JavaScript that nobody has claimed on npm \u2014 an attacker who publishes one lands code inside your build.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "supply_chain",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:typosquat",
    "tier": "pipeline",
    "label": "Lookalike domains",
    "summary": "Registered domains that impersonate yours to phish your staff and customers. Third-party DNS only \u2014 never contacts the lookalike host.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "typosquat",
    "impl": "",
    "caution": "resolves several hundred candidate domains per run"
  },
  {
    "key": "pipeline:correlate",
    "tier": "pipeline",
    "label": "Risk correlation",
    "summary": "Groups related findings per host into ranked attack chains.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "correlate",
    "impl": "",
    "caution": ""
  },
  {
    "key": "pipeline:notify",
    "tier": "pipeline",
    "label": "Alerting",
    "summary": "Delivers new findings to your configured channels.",
    "group": "Scan modules",
    "inputs": [
      {
        "name": "targets",
        "type": "hosts",
        "label": "Targets",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "result",
        "type": "json",
        "label": "Run summary",
        "required": false
      }
    ],
    "params": [
      {
        "name": "timeout",
        "kind": "int",
        "label": "Timeout (seconds)",
        "default": null,
        "required": false,
        "help": "Leave empty to use this module's configured budget.",
        "choices": []
      }
    ],
    "pipeline": "notify",
    "impl": "",
    "caution": ""
  },
  {
    "key": "source:target",
    "tier": "source",
    "label": "Target",
    "summary": "Feeds hostnames into the canvas. Scanning a domain you do not control is illegal in most jurisdictions \u2014 you are asserting you are authorised.",
    "group": "Input",
    "inputs": [],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Discovered hosts",
        "required": false
      }
    ],
    "params": [
      {
        "name": "hosts",
        "kind": "str",
        "label": "Hosts",
        "default": null,
        "required": true,
        "help": "One hostname per line, or comma-separated.",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "",
    "caution": "Owner-only. Every request is still rate-capped and SSRF-guarded."
  },
  {
    "key": "output:view",
    "tier": "output",
    "label": "Output",
    "summary": "Renders whatever is wired into it. Wire a run summary here to read it.",
    "group": "Output",
    "inputs": [
      {
        "name": "value",
        "type": "any",
        "label": "Value",
        "required": true
      }
    ],
    "outputs": [],
    "params": [],
    "pipeline": "",
    "impl": "",
    "caution": ""
  },
  {
    "key": "util:filter_hosts",
    "tier": "utility",
    "label": "Filter hosts",
    "summary": "Keeps only hosts containing (or not containing) a substring.",
    "group": "Utilities",
    "inputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Hosts",
        "required": true
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Filtered",
        "required": false
      }
    ],
    "params": [
      {
        "name": "contains",
        "kind": "str",
        "label": "Contains",
        "default": "",
        "required": false,
        "help": "Substring to match.",
        "choices": []
      },
      {
        "name": "invert",
        "kind": "bool",
        "label": "Exclude instead",
        "default": false,
        "required": false,
        "help": "",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "filter_hosts",
    "caution": ""
  },
  {
    "key": "util:merge_hosts",
    "tier": "utility",
    "label": "Merge hosts",
    "summary": "Combines two host lists, de-duplicated, order preserved.",
    "group": "Utilities",
    "inputs": [
      {
        "name": "a",
        "type": "hosts",
        "label": "Hosts A",
        "required": true
      },
      {
        "name": "b",
        "type": "hosts",
        "label": "Hosts B",
        "required": false
      }
    ],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Merged",
        "required": false
      }
    ],
    "params": [],
    "pipeline": "",
    "impl": "merge_hosts",
    "caution": ""
  },
  {
    "key": "util:pick_field",
    "tier": "utility",
    "label": "Pick field",
    "summary": "Pulls one field out of a run summary \u2014 e.g. `new` or `discovered`.",
    "group": "Utilities",
    "inputs": [
      {
        "name": "value",
        "type": "json",
        "label": "Value",
        "required": true
      }
    ],
    "outputs": [
      {
        "name": "value",
        "type": "json",
        "label": "Field",
        "required": false
      }
    ],
    "params": [
      {
        "name": "field",
        "kind": "str",
        "label": "Field name",
        "default": null,
        "required": true,
        "help": "",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "pick_field",
    "caution": ""
  },
  {
    "key": "util:analyse_cors",
    "tier": "utility",
    "label": "CORS verdict",
    "summary": "Decides whether response headers hand data to an arbitrary origin. Pure analysis \u2014 sends nothing.",
    "group": "Analysis",
    "inputs": [
      {
        "name": "headers",
        "type": "json",
        "label": "Response headers",
        "required": true
      }
    ],
    "outputs": [
      {
        "name": "verdict",
        "type": "json",
        "label": "Verdict",
        "required": false
      }
    ],
    "params": [
      {
        "name": "url",
        "kind": "str",
        "label": "URL (for the report)",
        "default": "",
        "required": false,
        "help": "",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "analyse_cors",
    "caution": ""
  },
  {
    "key": "util:fingerprint_waf",
    "tier": "utility",
    "label": "WAF fingerprint",
    "summary": "Names the WAF/CDN in front of a host from its response headers.",
    "group": "Analysis",
    "inputs": [
      {
        "name": "headers",
        "type": "json",
        "label": "Response headers",
        "required": true
      }
    ],
    "outputs": [
      {
        "name": "verdict",
        "type": "json",
        "label": "Products",
        "required": false
      }
    ],
    "params": [
      {
        "name": "url",
        "kind": "str",
        "label": "URL (for the report)",
        "default": "",
        "required": false,
        "help": "",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "fingerprint_waf",
    "caution": ""
  },
  {
    "key": "util:typosquat_candidates",
    "tier": "utility",
    "label": "Lookalike candidates",
    "summary": "Generates phishing-style lookalike domains for a name. Resolves nothing.",
    "group": "Analysis",
    "inputs": [],
    "outputs": [
      {
        "name": "hosts",
        "type": "hosts",
        "label": "Candidates",
        "required": false
      }
    ],
    "params": [
      {
        "name": "domain",
        "kind": "str",
        "label": "Domain",
        "default": null,
        "required": true,
        "help": "",
        "choices": []
      },
      {
        "name": "limit",
        "kind": "int",
        "label": "Max candidates",
        "default": 50,
        "required": false,
        "help": "",
        "choices": []
      }
    ],
    "pipeline": "",
    "impl": "typosquat_candidates",
    "caution": ""
  }
] as const;
