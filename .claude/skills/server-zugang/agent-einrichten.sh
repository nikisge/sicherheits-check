#!/usr/bin/env bash
# Richtet auf einem Server den Benutzer "claude-agent" ein: Login nur mit Schlüssel, darf nur lesen.
# Ändert nichts an SSH, Firewall oder Diensten. Aussperren kannst du dich damit nicht.
#
# Aufruf von deinem Rechner, einmal mit deinem Admin-Zugang (das Passwort tippst du ins Terminal, nie in einen Chat):
#   ssh root@DEIN-SERVER "AGENT_KEY='$(cat ~/.ssh/meinserver_agent.pub)' bash -s" < agent-einrichten.sh
#   (oder mit vorhandenem Admin-Schlüssel: ssh meinserver-admin "AGENT_KEY=..." ...)
# Nochmal ausführen ist harmlos (z. B. mit neuem Schlüssel, der alte fliegt dann raus).
set -euo pipefail
BENUTZER=claude-agent

# Programme an festen Orten suchen, in derselben Reihenfolge wie check.sh, damit die sudo-Regel passt
pfad() {
  for d in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /snap/bin; do [ -x "$d/$1" ] && { echo "$d/$1"; return; }; done
  echo "/usr/bin/$1"
}

[ "$(id -u)" = 0 ] || { echo "Abbruch: bitte als root ausführen."; exit 1; }
case "${AGENT_KEY:-}" in
  *PRIVATE*) echo "Abbruch: Das ist der PRIVATE Schlüssel. Auf den Server gehört nur die .pub-Zeile."; exit 1 ;;
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;;
  *) echo "Abbruch: AGENT_KEY fehlt oder ist kein öffentlicher Schlüssel."; exit 1 ;;
esac

# 1. Benutzer ohne Passwort ("*" heißt: es gibt keins, rein geht es nur mit dem Schlüssel)
id "$BENUTZER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$BENUTZER"
usermod --password '*' "$BENUTZER"

# 2. Gruppen: nur Logs lesen. Bewusst NICHT docker, denn wer docker darf, ist praktisch root.
for g in adm systemd-journal; do
  if getent group "$g" >/dev/null; then usermod -aG "$g" "$BENUTZER"; fi
done
if id -nG "$BENUTZER" | grep -qw docker; then gpasswd -d "$BENUTZER" docker >/dev/null; fi

# 3. Schlüssel hinterlegen. "restrict" schaltet Weiterleitungen und Terminal ab.
home=$(getent passwd "$BENUTZER" | cut -d: -f6)
install -d -m 700 -o "$BENUTZER" -g "$BENUTZER" "$home/.ssh"
printf 'restrict %s\n' "$AGENT_KEY" > "$home/.ssh/authorized_keys"
chown "$BENUTZER": "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"

# 4. Genau diese lesenden Befehle als root, sonst nichts (wie agent-sudoers, nur mit den Pfaden dieses Servers).
#    Erst auf Tippfehler prüfen, dann aktivieren: eine kaputte sudo-Datei würde sudo für alle lahmlegen.
D=$(pfad docker); U=$(pfad ufw); S=$(pfad sshd); N=$(pfad ss)
tmp=$(mktemp)
cat > "$tmp" <<EOF
$BENUTZER ALL=(root) NOPASSWD: $D ps, $D ps *, $D image inspect *, $D logs *, $U status, $S -T, $N -tulpnH
EOF
if visudo -cf "$tmp" >/dev/null; then
  install -m 440 "$tmp" /etc/sudoers.d/claude-agent
  rm -f "$tmp"
else
  rm -f "$tmp"; echo "Abbruch: sudo-Regel fehlerhaft, nichts aktiviert."; exit 1
fi

# 5. Kontrolle
echo "Fertig. $BENUTZER ist in den Gruppen: $(id -nG "$BENUTZER")"
echo "Erlaubt als root:"
sudo -l -U "$BENUTZER" | sed -n '/may run/,$p' | tail -n +2
for b in "$D" "$U" "$S" "$N"; do
  [ -x "$b" ] || echo "Hinweis: $b gibt es hier nicht, der Check überspringt diesen Teil."
done

# 6. Lässt SSH den neuen Benutzer überhaupt rein? (gehärtete Server haben oft eine Erlaubt-Liste)
ssh_cfg=$("$S" -T 2>/dev/null || true)
liste=$(printf '%s\n' "$ssh_cfg" | awk '$1=="allowusers" || $1=="allowgroups" {printf "%s ", $2}')
[ -n "$liste" ] && echo "ACHTUNG: SSH lässt nur diese Benutzer/Gruppen rein: $liste. Trag $BENUTZER dort ein (AllowUsers), sonst kommt der Agent nicht rein."
printf '%s\n' "$ssh_cfg" | grep -qx 'pubkeyauthentication no' && echo "ACHTUNG: Schlüssel-Login ist in der SSH-Konfiguration abgeschaltet."
if [ -n "$ssh_cfg" ] && ! printf '%s\n' "$ssh_cfg" | grep -q '^authorizedkeysfile .*\.ssh/authorized_keys'; then
  echo "ACHTUNG: SSH sucht Schlüssel nicht in ~/.ssh/authorized_keys ($(printf '%s\n' "$ssh_cfg" | grep '^authorizedkeysfile')). Schlüssel dort hinterlegen."
fi
exit 0
