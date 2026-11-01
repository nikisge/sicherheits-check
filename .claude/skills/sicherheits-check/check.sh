#!/usr/bin/env bash
# Sicherheits-Check für einen Linux-Server (getestet: Ubuntu 22.04/24.04, Debian 12/13, Rocky 9). Liest NUR, ändert nichts.
#
# Aufruf vom eigenen Rechner aus:   ssh agent@DEIN-SERVER 'bash -s' < check.sh
# Optional anderes Startdatum für die Log-Suche:   ssh agent@DEIN-SERVER 'SEIT=2026-10-17 bash -s' < check.sh
#
# Läuft als root oder als eingeschränkter Benutzer. Ohne root nutzt es nur die lesenden sudo-Befehle aus
# ../server-zugang/agent-sudoers (sudo -n, fragt nie nach einem Passwort). Fehlt eine Berechtigung, steht "(keine Berechtigung)" da.
# Gibt bewusst KEINE Umgebungsvariablen von Containern aus (da stehen Passwörter und API-Keys drin), sondern nur
# Versionsnummern aus den Images.

SEIT="${SEIT:-2026-10-17}"

priv() {
  if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@" 2>/dev/null || echo "(keine Berechtigung)"; fi
}

# Programme an festen Orten suchen, in derselben Reihenfolge wie agent-einrichten.sh, damit die sudo-Regel passt
# (Docker liegt z. B. als Snap unter /snap/bin, ss auf Rocky/Alma unter /usr/sbin).
pfad() {
  for d in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /snap/bin; do [ -x "$d/$1" ] && { echo "$d/$1"; return; }; done
  echo "/usr/bin/$1"
}
DOCKER=$(pfad docker); SSHD=$(pfad sshd); UFW=$(pfad ufw); SS=$(pfad ss)

echo "### SYSTEM"
. /etc/os-release 2>/dev/null && echo "os=$PRETTY_NAME"
echo "kernel=$(uname -r)"
echo "uptime=$(uptime -p)"
echo "pruefer=$(id -un)"
[ -f /var/run/reboot-required ] && echo "neustart_noetig=ja" || echo "neustart_noetig=nein"

echo "### UPDATES"
if command -v apt-get >/dev/null; then
  sim=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst')
  echo "offene_updates=$(printf '%s\n' "$sim" | grep -c .)"
  echo "davon_sicherheit=$(printf '%s\n' "$sim" | grep -c -i security)"
  printf '%s\n' "$sim" | grep -i security | awk '{print "  " $2}' | head -30
  dpkg -s unattended-upgrades >/dev/null 2>&1 && echo "auto_updates_paket=installiert" || echo "auto_updates_paket=fehlt"
  grep -h 'Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | sed 's/^/  /'
fi

echo "### SSH"
cfg=$(priv "$SSHD" -T)
if [ "$cfg" = "(keine Berechtigung)" ] || [ -z "$cfg" ]; then
  cfg=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '^\s*#' | tr 'A-Z' 'a-z')
  echo "quelle=Konfigurationsdateien (ungefähr)"
else
  echo "quelle=sshd -T (genau)"
fi
for k in port permitrootlogin passwordauthentication kbdinteractiveauthentication pubkeyauthentication maxauthtries; do
  printf '%s=%s\n' "$k" "$(printf '%s\n' "$cfg" | awk -v k="$k" '$1==k {print $2; exit}')"
done
echo "fail2ban=$(systemctl is-active fail2ban 2>/dev/null)"
fails=$(journalctl -u ssh -u sshd --since "7 days ago" --no-pager -q 2>/dev/null | grep -c -E 'Failed password|Invalid user')
[ "$fails" = 0 ] && [ -r /var/log/auth.log ] && fails=$(grep -c -E 'Failed password|Invalid user' /var/log/auth.log)
echo "fehlgeschlagene_logins_7_tage=$fails"
echo "benutzer_mit_shell=$(awk -F: '$7 ~ /(bash|sh|zsh)$/ {printf "%s ", $1}' /etc/passwd)"
echo "admin_gruppen=$(getent group sudo wheel | awk -F: '{printf "%s:%s ", $1, $4}')"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -r "$f" ] && awk -v f="$f" 'NF {print "  schluessel " f ": " $NF}' "$f"
done

echo "### FIREWALL"
if [ -x "$UFW" ]; then priv "$UFW" status | head -30; else echo "ufw=nicht installiert (Firewall evtl. beim Anbieter oder firewalld)"; fi

echo "### OFFENE_PORTE (lauscht auf dem Server)"
priv "$SS" -tulpnH | awk '{print "  " $1, $5, $7}'

echo "### DOCKER"
if [ -x "$DOCKER" ]; then
  echo "docker_client=$("$DOCKER" --version 2>/dev/null)"
  ps_out=$(priv "$DOCKER" ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}')
  printf '%s\n' "$ps_out" | sed 's/^/  container: /'
  echo "--- versionen aus den images (keine Umgebungsvariablen der Container)"
  printf '%s\n' "$ps_out" | cut -d'|' -f2 | sort -u | while read -r img; do
    [ -z "$img" ] || [ "$img" = "(keine Berechtigung)" ] && continue
    v=$(priv "$DOCKER" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}{{if .Config.Labels}}{{index .Config.Labels "org.opencontainers.image.version"}}{{end}}' "$img" \
        | grep -E '^(PHP_VERSION|NODE_VERSION|N8N_VERSION|NEXTCLOUD_VERSION|PYTHON_VERSION|NGINX_VERSION|OLLAMA_VERSION|[0-9v][0-9.]*)' | tr '\n' ' ')
    echo "  $img -> ${v:-keine Versionsangabe im Image}"
  done
  echo "--- abstuerze in container-logs seit $SEIT (Hinweis auf Speicherfehler-Exploits wie PHP2Shell)"
  printf '%s\n' "$ps_out" | cut -d'|' -f1 | while read -r name; do
    [ -z "$name" ] || [ "$name" = "(keine Berechtigung)" ] && continue
    n=$(priv "$DOCKER" logs --since "$SEIT" "$name" 2>&1 | grep -c -E 'Segmentation fault|SIGSEGV|exit signal|Allowed memory size .* exhausted')
    [ "$n" != 0 ] && echo "  $name: $n Treffer"
  done
  echo "  (Ende)"
else
  echo "docker=nicht installiert"
fi

echo "### PROGRAMME_AUF_DEM_SERVER"
command -v php >/dev/null && echo "php=$(php -r 'echo PHP_VERSION;' 2>/dev/null) sapi_module=$(ls /etc/apache2/mods-enabled/ 2>/dev/null | grep -o 'php[0-9.]*' | head -1)"
command -v node >/dev/null && echo "node=$(node -v)"
command -v n8n >/dev/null && echo "n8n=$(n8n --version 2>/dev/null)"
command -v python3 >/dev/null && echo "python=$(python3 -V 2>&1)"
dpkg-query -W -f='  paket ${Package} ${Version}\n' openssh-server apache2 nginx nodejs 'php*-fpm' 'libapache2-mod-php*' 2>/dev/null | grep -v ' $'
for f in /var/log/apache2/error.log /var/log/php*-fpm.log; do
  [ -r "$f" ] && echo "  abstuerze in $f: $(grep -c -E 'Segmentation fault|SIGSEGV|exit signal' "$f")"
done

echo "### OFFENE_GEHEIMNISSE (Dateien mit Passwörtern/Keys, die jeder Benutzer lesen kann, also auch der Agent)"
find /opt /srv /home /var/www /root -maxdepth 5 -name '.env*' -perm -o=r -type f 2>/dev/null | head -20 | sed 's/^/  env: /'
find /opt /srv /home /var/www /root -maxdepth 5 \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' \) -perm -o=r -type f -print0 2>/dev/null \
  | xargs -0 -r grep -l -i -E '(password|secret|api_key|token)[^:=]*[:=][[:space:]]*[^[:space:]$]' 2>/dev/null | head -20 | sed 's/^/  compose mit Klartext-Geheimnis: /'
echo "  (Ende)"

echo "### FERTIG"
