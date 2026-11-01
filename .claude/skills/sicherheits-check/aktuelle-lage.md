# Aktuelle Lage (Stand 2026-10-31)

Veraltet schnell. Das Frühwarnsystem (`../fruehwarnung/`) prüft live. Diese Liste ist der Spickzettel für den Check und
fürs Video. "Aktiv ausgenutzt" heißt: steht im CISA-Katalog der ausgenutzten Lücken (KEV, Stand 30.10., selbst
geprüft).

| Software | Was | Mindestens auf | Aktuell | Aktiv ausgenutzt? |
|---|---|---|---|---|
| **PHP** (PHP2Shell) | CVE-2026-109618/-109619, Codeausführung ohne Login, mod_php am schlimmsten | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; bis 8.1 kein Fix | | **ja**: seit 2026-10-26 |
| **Node.js** | Oktober-Release, u. a. CVE-2026-111497 (Brotli, Codeausführung) | 22.23.4 / 24.22.1 / 26.12.1; 18 + 20 ohne Updates | | **ja**: Brotli seit 2026-10-27 |
| **n8n** | Dutzende Lücken 2026, u. a. CVE-2026-21858 (CVSS 10, ohne Login), 3 kritische bis 2.22.1, Sandbox-Ausbruch bis 2.38.2 | neueste | 2.44.6 | **ja**: CVE-2025-68613 seit 2026-03-11 |
| **LiteLLM** | SQL-Injection in der Key-Prüfung, Befehlsausführung über MCP-Test, MCP-Auth-Umgehung; März: 1.82.7/1.82.8 mit Schadcode auf PyPI; 21.10.: 1.107.0 mit Passwort-Dieb (~2 h online) | neueste | 1.106.2 | **ja**: 3 Einträge (05-08, 06-08, 09-02) |
| **Langflow** | Codeausführung ohne Login (öffentlicher Flow-Build) | neueste | 1.12.8 | **ja**: CVE-2026-33017, CVE-2026-9198 |
| **Flowise** | >20 kritische Codeausführungen bis 3.1.4; SSO-Kontoübernahme (09-10) laut Advisory ohne Fix | neueste + SSO prüfen | 3.1.4 | nicht im KEV |
| **Coolify** | Codeausführung + Secret-Diebstahl (CVE-2026-34038) | neueste | 4.4.7 | nicht im KEV |
| **Open WebUI** | Sept.: Session-Token-Diebstahl über Links, OAuth-Login als fremder Nutzer | 0.11.4 | 0.12.3 | nicht im KEV |
| **Ollama** | Path-Traversal ohne Login über /api/pull (10-08) | neueste, Port nie öffentlich | 0.40.8 | nicht im KEV |
| **Nextcloud** | App "Built-in CODE Server" (Collabora) <26.4.303: Befehle ohne Login (CVE-2026-110447, 10-14), Deaktivieren reicht nicht | App 26.4.303 | Server 33.0.10 | laut Presse Angriffe seit 09-10 |
| **Traefik** | digestAuth komplett umgehbar (bis 3.7.10), NTLM-Wiederverwendung (bis 3.7.12) | 3.7.13 | 3.7.16 | nicht im KEV |
| **Portainer** | Admin-Anlage ohne Login (CVE-2026-55761), Host-Zugriff über Compose | 2.45.3 | 2.45.3 | nicht im KEV |
| **GitLab** | CVE-2026-97229, CVSS 10, Codeausführung ohne Login (10-12) | 19.2.8 / 19.3.5 / 19.4.2 | | **ja**: seit 2026-10-29 |
| **Python-Pakete brotli / brotlicffi** | CVE-2026-111497 (Brotli, wie bei Node) | neueste | | **ja**: seit 2026-10-27 |
| **Linux-Kernel** | CVE-2026-98432: Root übers Netz ohne Login, braucht MPTCP-Listener · Fragnesia CVE-2026-46300: lokal, laut CISA mit PHP2Shell verkettet | Updates der Distribution + Neustart; Ubuntu-Fix für 98432 noch offen (30.10.) | | Fragnesia **ja** seit 2026-10-28 · 98432 nein |

Plattformen statt Software (keine Version, sondern Keys tauschen):
- **Railway** (10-21): Angreifer an den Systemen mit den Umgebungsvariablen der Kunden. Alle Env-Variablen und
  Datenbank-Passwörter rotieren, Stripe-/OpenAI-Nutzung prüfen. Quelle: blog.railway.com.
- **OpenCode Console** (10-17 bis 10-19): API-Keys von 1,4 % der Nutzer offen, nur wer eine Mail bekam.
- **GhostAction** (10-08/09): bösartige GitHub-Workflows, ~1.900 Accounts. Eigene Workflows auf fremde Änderungen prüfen.

Quellen: GitHub Security Advisories der Projekte, CISA KEV
(cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), php.net, nodejs.org, Recherche-Datei.
