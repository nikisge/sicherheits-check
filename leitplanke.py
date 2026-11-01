#!/usr/bin/env python3
"""Leitplanke für Claude Code: blockt Befehle, die man nicht rückgängig machen kann.

Daten oder Volumes löschen, Datenbank leeren, Platte formatieren, sich aus SSH aussperren. Läuft als Hook vor jedem
Bash-Befehl und greift auch, wenn Claude ohne Nachfragen arbeitet. Aktiv über .claude/settings.json in diesem Ordner.

Ehrlich: Das ist eine Sperrliste, kein Panzer. Sie fängt Versehen und naheliegende Befehle ab, wer es darauf anlegt,
kommt drumherum. Das echte Rückgängig ist der Snapshot vor dem Fixen.
"""
import json
import re
import sys
from pathlib import Path

I = re.IGNORECASE
SPERREN = [
    (r"\brm\s+(-\w*[rR]|--recursive)", 0, "rekursiv löschen (rm -r)"),
    (r"\bfind\b[^|;&]*\s-delete\b", 0, "Dateien löschen (find -delete)"),
    (r"\b(shred|wipefs|mkfs(\.\w+)?|fdisk|sfdisk|parted)\b|\bdd\s[^|;&]*\bof=|>\s*/dev/(sd|vd|xvd|nvme)", 0,
     "Platte überschreiben oder formatieren"),
    (r"docker\s+(volume\s+(rm|prune)|system\s+prune)", 0, "Docker-Volumes löschen (da liegen die Daten)"),
    (r"docker[\s-]compose\b[^|;&]*\bdown\b[^|;&]*(\s-\w*v\b|--volumes)", 0, "Container samt Daten löschen (down -v)"),
    (r"docker\s+(container\s+)?rm\s[^|;&]*-\w*v", 0, "Container samt Volumes löschen"),
    (r"\b(DROP\s+(DATABASE|TABLE|SCHEMA)|TRUNCATE\s+(TABLE\s+)?\w|DELETE\s+FROM)\b|\b(dropdb|dropuser)\b", I,
     "Datenbank leeren oder löschen"),
    (r"\bsupabase\s+db\s+reset\b|\bprisma\s+(migrate\s+reset|db\s+push\b[^|;&]*--force-reset)", 0,
     "Datenbank zurücksetzen"),
    (r"\bcrontab\s+-r\b", 0, "alle Cronjobs löschen"),
    (r"\bapt(-get)?\s[^|;&]*(\bpurge\b|--purge)", 0, "Pakete samt Konfiguration löschen"),
    (r"\bgit\s+(push\s[^|;&]*(--force\b|\s-f\b)|reset\s+--hard|clean\s+-\w*f)", 0, "Git-Verlauf oder Dateien verwerfen"),
    (r"\b(userdel|deluser)\b", 0, "Benutzer löschen"),
    (r"\bufw\s+(reset|disable)\b|\biptables\s+-F\b|\bnft\s+flush\b", 0, "Firewall abschalten"),
    (r"(^|[\s;&|(])passwd(\s|$)|(sed\s+-i|tee|>>?)[^|;&]*(sshd_config|authorized_keys)", 0,
     "SSH-Zugang ändern (Gefahr, dass du dich aussperrst)"),
]


def mitgelesene_dateien(befehl, cwd):
    """Skripte, die der Befehl an den Server schickt (ssh host 'bash -s' < fix.sh) oder lokal startet (bash fix.sh)."""
    pfade = re.findall(r"(?<!<)<\s*([^\s<>|;&'\"]+)", befehl)
    pfade += re.findall(r"\b(?:bash|sh)\s+([^\s|;&<>'\"-][^\s|;&<>'\"]*)", befehl)
    for p in pfade:
        datei = (Path(cwd) / Path(p).expanduser()).resolve()
        if datei.is_file():
            yield p, datei.read_text(errors="replace")[:200_000]


def main():
    eingabe = json.load(sys.stdin)
    befehl = (eingabe.get("tool_input") or {}).get("command", "")
    texte = [("Befehl", befehl)] + list(mitgelesene_dateien(befehl, eingabe.get("cwd", ".")))
    for quelle, text in texte:
        for muster, flags, grund in SPERREN:
            if re.search(muster, text, flags):
                wo = "" if quelle == "Befehl" else f" (steht in {quelle})"
                print(f"Leitplanke: blockiert, weil {grund}{wo}. Das lässt sich nicht rückgängig machen. "
                      "Nicht über Umwege ausführen. Erklär dem Nutzer, warum es nötig ist, er entscheidet "
                      "und führt es selbst aus.", file=sys.stderr)
                sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
