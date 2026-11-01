#!/usr/bin/env bash
# Prüft von DEINEM Rechner aus, welche Ports deines Servers aus dem Internet erreichbar sind.
# Wichtig, weil Docker deine Firewall (ufw) umgehen kann: Der Server sagt "blockiert", von außen ist der Port trotzdem offen.
#
# Aufruf:  bash aussen-check.sh DEIN-SERVER 22 80 443 32768
# Ohne Ports werden typische Ports getestet.

host="$1"; shift
ports="${*:-22 80 443 3000 3001 5432 5678 6379 8000 8080 8081 8443 9000 11434 27017}"
[ -z "$host" ] && { echo "Aufruf: bash aussen-check.sh SERVER [PORTS...]"; exit 1; }

if [ "$(uname)" = Darwin ]; then to="-G 3"; else to="-w 3"; fi
echo "### AUSSEN_CHECK $host"
for p in $ports; do
  if nc -z $to "$host" "$p" >/dev/null 2>&1; then echo "  $p offen"; else echo "  $p zu"; fi
done
