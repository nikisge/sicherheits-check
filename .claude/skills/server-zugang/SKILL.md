---
name: server-zugang
description: Richtet einem Coding-Agenten (Claude Code, Codex) per SSH-Schlüssel Zugang zu einem Linux-Server (VPS) ein, auf einem von zwei Wegen - Admin-Zugang (voller Zugriff, eigener Schlüssel nur für diesen Server) oder Agent-Zugang (eigener Benutzer, darf nur 6 Befehle lesend ausführen). Nutzen, wenn jemand sagt "richte mir den Zugang / Admin-Zugang / Agent-Zugang für meinen Server ein", eine Server-IP nennt oder den Passwort-Login abschalten will. Nie mit Passwörtern im Chat.
---

# Server-Zugang: zwei Wege

Pfade in dieser Datei sind relativ zu diesem Skill-Ordner.

| | **Weg 1: Admin-Zugang** | **Weg 2: Agent-Zugang** |
|---|---|---|
| Wer meldet sich an | root (oder der Admin-Benutzer des Servers) | eigener Benutzer `claude-agent` |
| Was der Agent darf | alles, er fragt vor jedem Befehl | nur 6 lesende Befehle, die Grenze sitzt auf dem Server |
| Fixen | der Agent führt aus, du gibst jeden Befehl frei | der Agent sagt die Befehle, du führst sie aus |
| Schlüssel | mit Passwort, liegt im Schlüsselbund | ohne Passwort, geschützt durch die Grenze auf dem Server |
| Gut für | eigene Testprojekte, wenn es schnell gehen soll | alles, wo echte Daten oder Kunden dranhängen |

Beide Wege schließen sich nicht aus. Üblich ist: erst Weg 1, damit der Passwort-Login weg kann, dann Weg 2 für die
regelmäßigen Checks.

## Regeln für beide Wege
- **Nie nach Passwörtern fragen und keine annehmen.** Passwörter tippt der Nutzer nur in sein eigenes Terminal. Schreibt
  jemand ein Passwort in den Chat: nicht benutzen und raten, es zu ändern.
- `~/.ssh/config` **nie komplett anzeigen** (dort stehen oft andere Server). Nur gezielt nach dem neuen Kurznamen
  suchen (`grep -n "^Host <kurzname>$" ~/.ssh/config`) und neue Einträge unten **anhängen**.
- Jeder Server bekommt **eigene Schlüssel**. Nie einen vorhandenen Schlüssel wiederverwenden: wird er gestohlen,
  stünden sonst alle Server offen.
- Befehle, die Schlüssel auf den Server schreiben, führt **der Nutzer** in seinem eigenen Terminal aus. Du gibst ihm
  genau einen Befehl zum Kopieren und sagst vorher, was er abfragt.
- Erst klären: Server-IP und ein Kurzname (Standard `meinserver`). Hat der Server keinen root-Login (z. B. Benutzer
  `ubuntu` mit sudo), diesen Benutzer statt root nehmen.

## Weg 1: Admin-Zugang
1. Prüfen, dass `~/.ssh/<kurzname>_admin` und der Kurzname `<kurzname>-admin` noch frei sind.
2. Schlüssel erzeugen (das Passwort setzt der Nutzer gleich selbst):
   `ssh-keygen -t ed25519 -f ~/.ssh/<kurzname>_admin -C "<kurzname>-admin" -N "" -q`
3. Kurznamen anhängen:
   ```
   Host <kurzname>-admin
       HostName <server-ip>
       User root
       IdentityFile ~/.ssh/<kurzname>_admin
       IdentitiesOnly yes
       AddKeysToAgent yes
   ```
   Auf dem Mac zusätzlich `UseKeychain yes`.
4. Dem Nutzer **einen** Befehl für sein eigenes Terminal geben:
   - **Mac:** `ssh-keygen -p -f ~/.ssh/<kurzname>_admin && ssh-add --apple-use-keychain ~/.ssh/<kurzname>_admin && ssh-copy-id -f -i ~/.ssh/<kurzname>_admin.pub -o PubkeyAuthentication=no root@<server-ip>`
   - **Linux:** derselbe Befehl, nur `ssh-add ~/.ssh/<kurzname>_admin` ohne `--apple-use-keychain`.
   - **Windows** (Git Bash oder WSL, nicht PowerShell): `ssh-keygen -p -f ~/.ssh/<kurzname>_admin && cat ~/.ssh/<kurzname>_admin.pub | ssh -o PubkeyAuthentication=no root@<server-ip> "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"`

   Sag vorher, was gefragt wird: (1) zweimal ein neues Passwort für den Schlüssel, (2) auf dem Mac dasselbe noch
   einmal, dann liegt es im Schlüsselbund und muss nie wieder getippt werden, (3) das Root-Passwort des Servers.
   Kennt er das nicht: Beim Anbieter (Hetzner, Hostinger …) kann man es im Kundenbereich zurücksetzen.
   Warum der Admin-Schlüssel ein Passwort bekommt: Auf dem Server begrenzt ihn nichts. Wer die Datei vom Laptop
   kopiert, wäre sonst sofort root. Noch besser: Schlüssel in einem Passwortmanager mit SSH-Agent (z. B. 1Password),
   dann fragt jeder Zugriff nach einer Bestätigung.
5. Testen: `ssh -o BatchMode=yes -o ConnectTimeout=10 <kurzname>-admin 'id -un'` muss `root` liefern.
6. Einen groben Überblick nur mit Zahlen geben (System, Kerne, RAM, Platte, Zahl der Container), keine Namen von
   Containern, Projekten oder Ordnern.
7. Anbieten: **Passwort-Login abschalten** (siehe unten). Das ist der eigentliche Gewinn von Weg 1.

**Mit dem Admin-Zugang arbeiten:** Jeder Befehl einzeln, mit einem Satz davor, was er tut. Dem Nutzer sagen: Bei
ssh-Befehlen nie "nicht mehr fragen" wählen und keinen Modus ohne Rückfragen benutzen, sonst laufen ab da Root-Befehle
ohne ihn. Die Leitplanke (`leitplanke.py`) greift nur, wenn Claude Code im Ordner dieses Repos gestartet wurde.

## Weg 2: Agent-Zugang (nur lesen)
1. Prüfen, dass `~/.ssh/<kurzname>_agent` und `<kurzname>-agent` frei sind.
2. Schlüssel **ohne** Passwort erzeugen, weil der Agent ihn ohne Rückfrage benutzt:
   `ssh-keygen -t ed25519 -f ~/.ssh/<kurzname>_agent -C "claude-agent <kurzname>" -N "" -q`
3. Kurznamen anhängen:
   ```
   Host <kurzname>-agent
       HostName <server-ip>
       User claude-agent
       IdentityFile ~/.ssh/<kurzname>_agent
       IdentitiesOnly yes
   ```
4. Dem Nutzer **einen** Befehl für sein eigenes Terminal geben (absoluten Pfad zu `agent-einrichten.sh` einsetzen):
   - Gibt es schon den Admin-Zugang: `ssh <kurzname>-admin "AGENT_KEY='$(cat ~/.ssh/<kurzname>_agent.pub)' bash -s" < <pfad>/agent-einrichten.sh`
   - Sonst mit Root-Passwort: `ssh -o PubkeyAuthentication=no root@<server-ip> "AGENT_KEY='$(cat ~/.ssh/<kurzname>_agent.pub)' bash -s" < <pfad>/agent-einrichten.sh`

   Das Skript legt `claude-agent` ohne Passwort an, hinterlegt den Schlüssel mit `restrict` und erlaubt per sudo genau
   die Befehle aus `agent-sudoers`. An SSH, Firewall und Diensten ändert es nichts, aussperren kann man sich damit
   nicht. Steht am Ende "ACHTUNG", den Satz zuerst lösen.
5. Testen, beides muss stimmen:
   - Lesen klappt: `ssh -o BatchMode=yes <kurzname>-agent 'sudo -n -l'` und `ssh <kurzname>-agent 'sudo -n docker ps -q | wc -l'`
   - Ändern wird abgelehnt: `ssh <kurzname>-agent 'sudo -n docker stop gibt-es-nicht'`

Die 6 erlaubten Befehle: `docker ps`, `docker image inspect`, `docker logs`, `ufw status`, `sshd -T`, `ss -tulpn`.
Bewusst nicht: die docker-Gruppe (wer docker darf, ist praktisch root), Container-Einstellungen auslesen (da stehen
Passwörter drin), alles, was etwas ändert. "Nur lesen" heißt trotzdem: Der Agent sieht alles, was jeder Benutzer lesen
kann. Für alle lesbare `.env`-Dateien meldet der Sicherheits-Check, Fix ist `chmod 600`.

## Passwort-Login abschalten
Vorher alle vier Punkte bestätigen lassen: Schlüssel-Login getestet, Snapshot beim Anbieter gemacht, ein zweites
Terminal offen, die Web-Konsole des Anbieters offen. Dann bekommt der Nutzer diesen Befehl für sein Terminal:

`ssh <kurzname>-admin "printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/00-nur-schluessel.conf && sshd -t && (systemctl reload ssh || systemctl reload sshd)"`

Die `00-` vorne ist wichtig: Die erste Angabe gewinnt, und manche Anbieter legen eine Datei an, die Passwörter wieder
erlaubt. Danach im zweiten Terminal testen: `ssh <kurzname>-admin 'id -un'` klappt, und
`ssh -o PubkeyAuthentication=no root@<server-ip>` endet mit "Permission denied (publickey)".
Wer sich sonst noch per Passwort anmeldet (Kollegen, VS Code Remote), braucht vorher einen eigenen Schlüssel.
