# Sicherheits-Check für deinen Server und deine Projekte, mit Claude Code oder Codex

Aus meinem YouTube-Video „Cyber Security mit Claude Code“ ([Kanal](https://www.youtube.com/@niklas.hansen)).
Für alle, die mit KI bauen und ihren Server oder ihre Projekte noch nie richtig abgesichert haben. Kein Wissen über
Security nötig, dein Coding-Agent macht die Arbeit und erklärt dir jeden Schritt.

> **Für KI-Agenten:** Lies zuerst [`AGENTS.md`](AGENTS.md) und arbeite nach dem passenden Skill.

Drei Skills sind drin:

| Skill | Was er macht |
|---|---|
| [**server-zugang**](.claude/skills/server-zugang/SKILL.md) | gibt deinem Agenten per SSH-Schlüssel Zugang zu deinem Server, auf einem von zwei Wegen (siehe unten). Nie mit Passwort im Chat. |
| [**sicherheits-check**](.claude/skills/sicherheits-check/SKILL.md) | prüft deinen Server nur lesend: offene Ports, SSH, veraltete Software in Containern, Absturzspuren, offen lesbare Passwörter. Danach Fixes Schritt für Schritt, nach Snapshot. |
| [**fruehwarnung**](.claude/skills/fruehwarnung/SKILL.md) | liest die CISA-Liste der Lücken, die gerade aktiv ausgenutzt werden, gleicht sie mit deinen GitHub-Projekten und deinem Server ab und arbeitet die Fixes mit dir ab. |

## Loslegen

**Schnell:** Kopier den Link zu diesem Repo in Claude Code oder Codex und schreib dazu, was du willst (Beispiele unten).
Der Agent holt sich das Repo und arbeitet nach den Anleitungen hier.

**Am sichersten:** Repo klonen und den Agenten in diesem Ordner starten. Dann ist bei Claude Code die Leitplanke aktiv
und die Skills sind direkt als `/server-zugang`, `/sicherheits-check` und `/fruehwarnung` da.

```bash
git clone https://github.com/nikisge/sicherheits-check ~/sicherheits-check
cd ~/sicherheits-check
claude
```

## Zwei Wege, deinem Agenten Zugang zu geben

Nie dein Root-Passwort in den Chat kopieren. Es landet im Klartext im Verlauf. Der Agent bekommt stattdessen einen
eigenen SSH-Schlüssel nur für diesen Server.

| | **Weg 1: Admin-Zugang** | **Weg 2: Agent-Zugang** |
|---|---|---|
| Was der Agent darf | alles, er fragt dich vor jedem Befehl | nur 6 lesende Befehle, die Grenze sitzt auf dem Server |
| Wer fixt | der Agent, du gibst jeden Befehl frei | du, der Agent sagt dir die Befehle und prüft danach |
| Gut für | eigene Testprojekte, wenn es schnell gehen soll | alles, wo echte Daten oder Kunden dranhängen |

Die Prompts aus dem Video:

**Weg 1:**
> Richte mir den vollen Admin-Zugang für meinen Server ein. IP: DEINE-IP. Erstell dafür einen neuen Schlüssel nur für diesen Server. (Link zu diesem Repo)

Der Agent erzeugt den Schlüssel und gibt dir **einen** Befehl für dein eigenes Terminal. Der fragt nach einem Passwort
für den Schlüssel und einmal nach deinem Root-Passwort. Danach empfiehlt der Agent, den Passwort-Login abzuschalten,
damit niemand mehr mit einem erratenen Passwort reinkommt.

**Weg 2:**
> Der Admin-Zugang klappt. Richte mir jetzt zusätzlich den beschränkten Agent-Zugang ein, mit eigenem Schlüssel.

Ein eigener Benutzer `claude-agent`, der nur das darf: `docker ps`, `docker image inspect`, `docker logs`,
`ufw status`, `sshd -T`, `ss -tulpn`. Ändern, löschen oder Container-Passwörter auslesen geht nicht.
Weg 2 klappt auch ohne Weg 1, dann fragt der Einrichtungsbefehl einmal nach deinem Root-Passwort.

Dein Root-Passwort findest oder setzt du im Kundenbereich deines Anbieters zurück (bei Hetzner zum Beispiel über
„Rescue“, bei Hostinger in der VPS-Übersicht).

## Server prüfen
> Schau bitte auf meinem Server, ob da Unsicherheiten sind. Schau dir die neuesten Sicherheitslücken im Internet an und check erst mal nur lesend, was davon meinen Server betrifft und wie ich ihn besser absichern kann.

Bevor irgendwas geändert wird: **Snapshot** bei deinem Anbieter (ein Klick, das ist dein Rückgängig-Knopf).

## Frühwarnung für deine Projekte
> /fruehwarnung prüf meine Projekte in ~/projekte

oder ohne Slash-Befehl:

> Welche Sicherheitslücken werden gerade aktiv ausgenutzt, und betrifft davon etwas meine GitHub-Projekte?

Der Agent liest die aktuelle [CISA-Liste](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), sammelt die
Versionen aus deinen Projekten (`package.json`, `requirements.txt`, `pyproject.toml`, `composer.json`, `go.mod`,
`Dockerfile`, `docker-compose.yml`) und sagt dir, was betroffen ist. Fixes macht er erst nach deinem OK, auf einem
eigenen Branch, mit Tests.

Das Skript dahinter geht auch ohne Agent:

```bash
cd ~/sicherheits-check/.claude/skills/fruehwarnung
python3 fruehwarnung.py lage --tage 30                                   # was wird gerade ausgenutzt?
python3 fruehwarnung.py inventar --projekt ~/projekte > /tmp/inventar.json
python3 fruehwarnung.py pruefen /tmp/inventar.json                       # was davon betrifft mich?
```

Regelmäßig aufs Handy, mit Claude-Erklärung oder als Reaktion auf den
[CISA-Newsletter](https://www.cisa.gov/about/contact-us/subscribe-updates-cisa): siehe
[fruehwarnung/SKILL.md](.claude/skills/fruehwarnung/SKILL.md#regelmäßig-laufen-lassen-nur-melden).

## Die Leitplanke
[`leitplanke.py`](leitplanke.py) läuft bei Claude Code vor jedem Befehl, wenn du Claude in diesem Ordner startest. Sie
blockt Dinge, die man nicht rückgängig machen kann: Daten oder Docker-Volumes löschen, Datenbank leeren, Platte
formatieren, Firewall abschalten, SSH-Zugang ändern. Auch wenn du aus Versehen „ja“ klickst.
Ehrlich: Das ist eine Sperrliste, kein Panzer. Gegen alles andere hilft der Snapshot.

## Ehrliche Grenzen
- Getestet auf Ubuntu 22.04 und 24.04, Debian 12 und 13, Rocky Linux 9, auch mit Docker als Snap.
- **Kein Ersatz für Profis.** Die Tipps richten sich an Privatpersonen und kleine Teams.
- Findet bekannte Lücken und typische Fehler in der Einrichtung, keine Fehler in deinem eigenen Code. Dafür gibt es den
  [Security Audit Skill von Cloudflare](https://github.com/cloudflare/security-audit-skill), am besten mehrmals laufen lassen.
- **Shared Hosting** (kein Root-Zugang): Den PHP-Patch macht der Anbieter. Prüf im Panel, dass du eine PHP-Version
  nutzt, die noch Updates bekommt (8.2 oder neuer).
- **Railway, Vercel, Render & Co.** (kein eigener Server): Keys tauschen und neu deployen, damit das aktuelle
  Basis-Image genutzt wird. Die Frühwarnung für deine Projekte funktioniert trotzdem.
- Nutzung auf eigene Verantwortung. Vor jeder Änderung: Snapshot.

## Lizenz
MIT. Nimm es, bau es um, teil es.
