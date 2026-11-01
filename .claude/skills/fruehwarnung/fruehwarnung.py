#!/usr/bin/env python3
"""Frühwarnung: Welche aktuellen Sicherheitslücken betreffen MEINE Projekte und Server?

Meldet nur. Das Skript repariert nichts und braucht keinen Zugang zu deinem Server. Das ist Absicht: Ein Programm, das
fremde Texte aus dem Internet liest, soll nicht gleichzeitig etwas ändern dürfen. Den Fix macht dein Agent danach mit
dir zusammen (siehe SKILL.md).

Aufruf:
  python3 fruehwarnung.py lage [--tage 30]
      Was gerade aktiv ausgenutzt wird: neue Einträge der CISA-Liste (Known Exploited Vulnerabilities).
  python3 fruehwarnung.py inventar --projekt ORDNER [ORDNER ...] [--tief] > inventar.json
      Versionen aus deinen Projekten: package.json (+ package-lock.json), requirements*.txt, pyproject.toml
      (+ uv.lock / poetry.lock), composer.json (+ composer.lock), go.mod, Dockerfile, docker-compose.
      --tief nimmt alle Pakete aus den Lock-Dateien, nicht nur die direkten.
  python3 fruehwarnung.py inventar --check bericht.txt > inventar.json
      Versionen aus der Ausgabe von check.sh (Sicherheits-Check des Servers).
  python3 fruehwarnung.py pruefen inventar.json [--neu] [--tage 90]
      Gleicht das Inventar ab. --neu zeigt nur, was seit dem letzten Lauf dazugekommen ist.

Quellen (öffentlich, ohne Konto):
  CISA KEV-Liste                  Lücken, die nachweislich aktiv ausgenutzt werden (dieselbe Liste wie im CISA-Newsletter)
  api.osv.dev                     bekannte Lücken für Pakete (npm, PyPI, Packagist, Go)
  nodejs.org + Node-Release-Plan  Node-Releases mit Markierung "security", Ende der Updates je Version
  php.net/releases                neueste PHP-Version je Zweig, mit Tag "security"
  endoflife.date                  Python: Ende der Updates je Version
Systempakete (openssh, libc, Kernel ...) deckt das nicht ab, die erledigen die automatischen Updates des Systems.
"""
import datetime
import json
import os
import pathlib
import re
import sys
import urllib.request

HEUTE = datetime.date.today()
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
# PHP-Zweige ohne Sicherheitsupdates (Stand 2026-10: 8.1 und älter, Quelle php.net/supported-versions)
PHP_LETZTER_TOTER_ZWEIG = (8, 1)
SCHWERE = {'CRITICAL': 4, 'HIGH': 3, 'MODERATE': 2, 'MEDIUM': 2, 'LOW': 1}
REIHENFOLGE = {'ROT': 0, 'GELB': 1, 'GRAU': 2, 'GRÜN': 3}
UEBERSPRINGEN = {'node_modules', '.git', '.venv', 'venv', 'env', 'vendor', 'dist', 'build', '__pycache__', '.next',
                 'target', '.cache', '.tox', 'site-packages'}
# Wörter, die beim Namensabgleich mit der CISA-Liste zu viel Rauschen erzeugen
STOPPWOERTER = {'the', 'and', 'for', 'core', 'server', 'client', 'api', 'http', 'web', 'app', 'plugin', 'utils',
                'util', 'common', 'sdk', 'cli', 'lib', 'tools', 'types', 'config', 'data', 'base', 'manager'}

_cache = {}


def hole(url, daten=None):
    schluessel = url + (json.dumps(daten, sort_keys=True) if daten else '')
    if schluessel in _cache:
        return _cache[schluessel]
    req = urllib.request.Request(url, data=json.dumps(daten).encode() if daten else None,
                                 headers={'User-Agent': 'fruehwarnung/2.0 (github.com/nikisge/sicherheits-check)',
                                          'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        antwort = json.load(r)
    _cache[schluessel] = antwort
    return antwort


def vt(v):
    """'v22.23.1' -> (22, 23, 1); zum Vergleichen von Versionen."""
    return tuple(int(x) for x in re.findall(r'\d+', str(v).split('-')[0].split('+')[0])[:4])


# ---------------------------------------------------------------- CISA-Liste

def kev():
    """CISA-Liste der aktiv ausgenutzten Lücken, einmal pro Tag geladen (~1,5 MB)."""
    ordner = pathlib.Path.home() / '.cache' / 'fruehwarnung'
    datei = ordner / f'kev-{HEUTE.isoformat()}.json'
    if datei.exists():
        return json.loads(datei.read_text())
    daten = hole(KEV_URL)
    ordner.mkdir(parents=True, exist_ok=True)
    for alt in ordner.glob('kev-*.json'):
        if alt != datei:
            alt.unlink()
    datei.write_text(json.dumps(daten))
    return daten


def lage(tage):
    d = kev()
    grenze = HEUTE - datetime.timedelta(days=tage)
    neu = sorted((v for v in d['vulnerabilities'] if v.get('dateAdded', '') >= grenze.isoformat()),
                 key=lambda v: v['dateAdded'], reverse=True)
    zeilen = [f"# CISA: aktiv ausgenutzte Lücken, neu auf der Liste seit {grenze.isoformat()}",
              f"{len(neu)} Einträge · Katalog-Stand {d.get('dateReleased', '')[:10]} · insgesamt {d.get('count')}",
              'Quelle: https://www.cisa.gov/known-exploited-vulnerabilities-catalog', '']
    for v in neu[:80]:
        ransom = ' · Ransomware' if v.get('knownRansomwareCampaignUse') == 'Known' else ''
        zeilen.append(f"- {v['dateAdded']} · {v['vendorProject']} {v['product']} · {v['cveID']}{ransom}: "
                      f"{v.get('shortDescription', '')[:170]}")
    if len(neu) > 80:
        zeilen.append(f'- … und {len(neu) - 80} weitere')
    return '\n'.join(zeilen)


def woerter(text):
    return {w for w in re.split(r'[^a-z0-9]+', text.lower()) if len(w) >= 3 and w not in STOPPWOERTER}


def namens_treffer(e, kev_daten, tage):
    """CISA-Einträge der letzten Tage, deren Produktname zum Paket passt. Der Agent prüft danach, ob die Version
    wirklich betroffen ist (das steht nicht maschinenlesbar in der Liste)."""
    name = e.get('anzeige') or e['name']
    if re.match(r'(github\.com|golang\.org|gitlab\.com)/', name):         # Go-Modul: nur Projektteil, ohne /v3
        teile = [t for t in name.split('/')[1:] if not re.fullmatch(r'v\d+', t)]
        name = ' '.join(teile[-2:])
    eigene = woerter(name)
    if not eigene:
        return []
    grenze = (HEUTE - datetime.timedelta(days=tage)).isoformat()
    treffer = []
    for v in kev_daten:
        if v.get('dateAdded', '') < grenze:
            continue
        if eigene & woerter(v['product']) or re.sub(r'[^a-z0-9]', '', name.lower()) == \
                re.sub(r'[^a-z0-9]', '', v['product'].lower()):
            treffer.append(v)
    return treffer


# ---------------------------------------------------------------- Prüfungen je Software

def pruefe_node(e):
    v = vt(e['version'])
    plan = hole('https://raw.githubusercontent.com/nodejs/Release/main/schedule.json')
    ende = (plan.get(f'v{v[0]}') or {}).get('end')
    if ende and datetime.date.fromisoformat(ende) < HEUTE:
        return 'ROT', f'Node {v[0]} bekommt seit {ende} keine Sicherheitsupdates mehr. Auf eine aktuelle LTS wechseln.', []
    if len(v) < 3:
        return 'GELB', (f'Nur Hauptversion {v[0]} angegeben (z. B. Image-Tag). Beim nächsten Bauen mit --pull wird die '
                        f'neueste {v[0]}er gezogen. Genaue Version prüfen: node -v im Container.'), []
    neuer = [r for r in hole('https://nodejs.org/dist/index.json')
             if vt(r['version'])[0] == v[0] and vt(r['version']) > v]
    if not neuer:
        return 'GRÜN', 'aktuell', []
    neueste = max(neuer, key=lambda r: vt(r['version']))['version']
    sicher = sorted((r for r in neuer if r.get('security')), key=lambda r: vt(r['version']))
    if sicher:
        liste = ', '.join(f"{r['version']} ({r['date']})" for r in sicher)
        return 'ROT', f'Sicherheits-Releases seit deiner Version: {liste}. Auf {neueste} aktualisieren.', \
            [r['version'] for r in sicher]
    return 'GELB', f'Neuere Version {neueste} verfügbar (ohne Sicherheitsfix).', []


def pruefe_php(e):
    v = vt(e['version'])
    if len(v) < 2:
        return 'GRAU', 'Nur Hauptversion angegeben, genaue PHP-Version unbekannt.', []
    if v[:2] <= PHP_LETZTER_TOTER_ZWEIG:
        return 'ROT', f'PHP {v[0]}.{v[1]} bekommt keine Sicherheitsupdates mehr. Auf 8.3 oder neuer wechseln.', []
    if len(v) < 3:
        return 'GELB', f'Nur Zweig {v[0]}.{v[1]} angegeben. Beim Bauen mit --pull kommt die neueste {v[0]}.{v[1]}.x.', []
    info = hole(f'https://www.php.net/releases/index.php?json&version={v[0]}.{v[1]}')
    neueste = info.get('version', '')
    if not neueste or vt(neueste) <= v:
        return 'GRÜN', 'aktuell', []
    if 'security' in (info.get('tags') or []):
        return 'ROT', f'Sicherheits-Release {neueste} vom {info.get("date")}. Aktualisieren (bei Docker: Image neu bauen).', [neueste]
    return 'GELB', f'Neuere Version {neueste} verfügbar.', []


def pruefe_python(e):
    v = vt(e['version'])
    if len(v) < 2:
        return 'GRAU', 'Nur Hauptversion angegeben, genaue Python-Version unbekannt.', []
    zweig = next((z for z in hole('https://endoflife.date/api/python.json') if z.get('cycle') == f'{v[0]}.{v[1]}'), None)
    if not zweig:
        return 'GRAU', f'Python {v[0]}.{v[1]} ist bei endoflife.date nicht gelistet', []
    ende = zweig.get('eol')
    if isinstance(ende, str) and datetime.date.fromisoformat(ende) < HEUTE:
        return 'ROT', f'Python {v[0]}.{v[1]} bekommt seit {ende} keine Sicherheitsupdates mehr. Auf eine aktuelle Version wechseln.', []
    neueste = zweig.get('latest', '')
    if len(v) >= 3 and neueste and vt(neueste) > v:
        return 'GELB', f'Neuere Version {neueste} verfügbar (Python-Patches enthalten oft Sicherheitsfixes).', []
    return 'GRÜN', 'aktuell', []


def neueste_paketversion(name, oeko):
    try:
        if oeko == 'npm':
            return hole(f'https://registry.npmjs.org/{name}/latest')['version']
        if oeko == 'PyPI':
            return hole(f'https://pypi.org/pypi/{name}/json')['info']['version']
    except Exception:
        pass
    return None


def osv_vorpruefung(eintraege):
    """Fragt OSV in einem Rutsch, welche Pakete überhaupt Lücken haben. Spart hunderte Einzelabfragen."""
    abfragen = sorted({(e['name'], e['oekosystem'], e['version']) for e in eintraege if e.get('oekosystem')})
    betroffen = set()
    for i in range(0, len(abfragen), 500):
        teil = abfragen[i:i + 500]
        antwort = hole('https://api.osv.dev/v1/querybatch', {'queries': [
            {'package': {'name': n, 'ecosystem': o}, 'version': v} for n, o, v in teil]})
        for (n, o, v), r in zip(teil, antwort.get('results', [])):
            if r.get('vulns'):
                betroffen.add((n, o, v))
    return betroffen


def pruefe_osv(e, betroffen, kev_cves):
    if betroffen is not None and (e['name'], e['oekosystem'], e['version']) not in betroffen:
        return 'GRÜN', 'keine bekannten Lücken', []
    antwort = hole('https://api.osv.dev/v1/query',
                   {'package': {'name': e['name'], 'ecosystem': e['oekosystem']}, 'version': e['version']})
    luecken, gesehen = [], set()
    for x in antwort.get('vulns', []):
        cves = tuple(sorted(a for a in x.get('aliases', []) + [x['id']] if a.startswith('CVE')))
        schluessel = cves or (x['id'],)
        if schluessel in gesehen:      # dieselbe Lücke steht oft doppelt drin (GHSA + GO/PYSEC)
            continue
        gesehen.add(schluessel)
        schwere = ((x.get('database_specific') or {}).get('severity') or 'UNBEKANNT').upper()
        behoben = sorted({ev['fixed'] for a in x.get('affected', []) for r in a.get('ranges', [])
                          for ev in r.get('events', []) if ev.get('fixed')}, key=vt)
        aktiv = next((kev_cves[c]['dateAdded'] for c in cves if c in kev_cves), None)
        luecken.append({'id': x['id'], 'cve': ', '.join(schluessel), 'schwere': schwere, 'aktiv_seit': aktiv,
                        'titel': (x.get('summary') or '').strip(), 'behoben': behoben,
                        'datum': x.get('published', '')[:10]})
    if not luecken:
        return 'GRÜN', 'keine bekannten Lücken', []
    luecken.sort(key=lambda l: l['datum'], reverse=True)                       # neueste zuerst ...
    luecken.sort(key=lambda l: -SCHWERE.get(l['schwere'], 0))                   # ... innerhalb der Schwere ...
    luecken.sort(key=lambda l: 0 if l['aktiv_seit'] else 1)                     # ... aktiv ausgenutzte ganz oben
    zaehler = {}
    for l in luecken:
        zaehler[l['schwere']] = zaehler.get(l['schwere'], 0) + 1
    kopf = f"{len(luecken)} bekannte Lücken (" + ', '.join(
        f'{n}× {s}' for s, n in sorted(zaehler.items(), key=lambda t: -SCHWERE.get(t[0], 0))) + ')'
    aktive = [l for l in luecken if l['aktiv_seit']]
    if aktive:
        kopf += (f", davon {'1 Lücke, die' if len(aktive) == 1 else f'{len(aktive)} Lücken, die'} laut CISA "
                 f"AKTIV AUSGENUTZT {'wird' if len(aktive) == 1 else 'werden'}")
    neueste = neueste_paketversion(e['name'], e['oekosystem'])
    if neueste:
        kopf += f'. Neueste Version: {neueste}'
    ampel = 'ROT' if aktive or any(SCHWERE.get(l['schwere'], 0) >= 3 for l in luecken) else 'GELB'
    return ampel, kopf, luecken


def pruefe(e, betroffen, kev_cves):
    if e.get('unbekannt'):
        return 'GRAU', e.get('hinweis') or 'Version nicht gefunden, bitte von Hand ins Inventar eintragen', []
    if e.get('oekosystem'):
        return pruefe_osv(e, betroffen, kev_cves)
    if e['name'] == 'node':
        return pruefe_node(e)
    if e['name'] == 'php':
        return pruefe_php(e)
    if e['name'] == 'python':
        return pruefe_python(e)
    return 'GRAU', 'keine Versionsquelle hinterlegt', []


# ---------------------------------------------------------------- Bericht

def pruefen(inventar, nur_neu=False, tage=90):
    zustand_datei = pathlib.Path(inventar['_pfad']).with_suffix('.gesehen.json')   # Gedächtnis je Inventar
    gesehen = set(json.loads(zustand_datei.read_text())) if zustand_datei.exists() else set()
    zeilen = [f"# Frühwarnung {inventar.get('name', '')} · {HEUTE.isoformat()}".replace('  ', ' ')]
    try:
        kev_daten = kev()
        kev_liste = kev_daten['vulnerabilities']
        zeilen.append(f"CISA-Liste Stand {kev_daten.get('dateReleased', '')[:10]} ({kev_daten.get('count')} aktiv "
                      f"ausgenutzte Lücken) · Lücken-Datenbank OSV · nodejs.org · php.net · endoflife.date\n")
    except Exception as fehler:
        kev_liste = []
        zeilen.append(f'ACHTUNG: CISA-Liste nicht erreichbar ({fehler}). Abgleich nur gegen OSV.\n')
    kev_cves = {v['cveID']: v for v in kev_liste}

    # gleiche Software in mehreren Projekten nur einmal prüfen
    gruppen = {}
    for e in inventar['software']:
        k = (e['name'], e.get('oekosystem', ''), e['version'])
        g = gruppen.setdefault(k, dict(e, wo=[]))
        if e.get('wo'):
            g['wo'].append(e['wo'] + (' (dev)' if e.get('dev') else '') + (' (Version ungefähr)' if e.get('ungefaehr') else ''))
    try:
        betroffen = osv_vorpruefung(gruppen.values())
    except Exception:
        betroffen = None                          # dann eben einzeln abfragen

    jetzt, ergebnisse, gruen, grau = set(), [], [], []
    for e in gruppen.values():
        try:
            ampel, text, details = pruefe(e, betroffen, kev_cves)
        except Exception as fehler:
            ampel, text, details = 'GRAU', f'Abfrage fehlgeschlagen: {fehler}', []
        namen = [v for v in namens_treffer(e, kev_liste, tage)
                 if not any(v['cveID'] in d.get('cve', '') for d in details if isinstance(d, dict))]
        if namen and ampel in ('GRÜN', 'GRAU'):
            ampel = 'GELB'
        ids = {d['id'] if isinstance(d, dict) else f"{e['name']}@{d}" for d in details} | {v['cveID'] for v in namen}
        jetzt |= ids
        neu = ids - gesehen
        if nur_neu and not neu:
            continue
        if ampel == 'GRÜN':
            gruen.append(e)
        elif ampel == 'GRAU' and not namen and e.get('nur_name'):
            grau.append(e)
        else:
            ergebnisse.append((ampel, e, text, details, namen, neu))

    for ampel, e, text, details, namen, neu in sorted(ergebnisse, key=lambda t: REIHENFOLGE[t[0]]):
        wo = f" · {', '.join(e['wo'][:4])}{' …' if len(e['wo']) > 4 else ''}" if e['wo'] else ''
        zeilen.append(f"## {ampel} · {e.get('anzeige', e['name'])} {e['version']}{wo}\n{text}")
        dicts = [d for d in details if isinstance(d, dict)]
        for d in dicts[:5]:
            markierung = ' **NEU**' if d['id'] in neu and gesehen else ''
            aktiv = f" **AKTIV AUSGENUTZT laut CISA seit {d['aktiv_seit']}**" if d['aktiv_seit'] else ''
            fix = f" → behoben in {', '.join(d['behoben'][-3:])}" if d['behoben'] else ''
            zeilen.append(f"- {d['schwere']} {d['cve']} ({d['datum']}){aktiv}: {d['titel'][:110]}{fix}{markierung}")
        if len(dicts) > 5:
            zeilen.append(f"- … und {len(dicts) - 5} weitere")
        for v in namen[:3]:
            zeilen.append(f"- PRÜFEN: CISA-Eintrag {v['dateAdded']} zu {v['vendorProject']} {v['product']} "
                          f"({v['cveID']}): {v.get('shortDescription', '')[:120]} Betrifft das diese Version?")
        zeilen.append('')
    if gruen:
        zeilen.append(f"Ohne bekannte Lücken: {len(gruen)} Einträge.")
    if grau:
        zeilen.append("Nicht nach Version geprüft (nur CISA-Namensabgleich, ohne Treffer): "
                      + ', '.join(sorted({f"{e.get('anzeige', e['name'])} {e['version']}" for e in grau})))
    if nur_neu and not ergebnisse:
        zeilen.append('Nichts Neues seit dem letzten Lauf.')
    zustand_datei.write_text(json.dumps(sorted(gesehen | jetzt)))
    return '\n'.join(zeilen)


# ---------------------------------------------------------------- Inventar aus Projekten

def ungefaehre_version(spez):
    """'^1.2.3' / '>=1.2' / '~=2.0' -> ('1.2.3', True); 'git+https…' / '*' -> (None, …)."""
    m = re.search(r'(\d+(?:\.\d+){0,3})', spez or '')
    if not m or re.match(r'\s*(git|http|file:|link:|workspace:|github:|npm:)', spez or ''):
        return None, True
    exakt = bool(re.fullmatch(r'\s*(==|=)?\s*v?\d+(\.\d+){2,3}\S*\s*', spez))
    return m.group(1), not exakt


def pypi_name(n):
    return re.sub(r'[-_.]+', '-', n).lower()


def toml_pakete(text):
    """[[package]] name/version aus uv.lock oder poetry.lock (ohne toml-Bibliothek, läuft ab Python 3.8)."""
    pakete = {}
    for block in re.split(r'^\[\[package\]\]\s*$', text, flags=re.M)[1:]:
        n = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        v = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if n and v:
            pakete[pypi_name(n.group(1))] = v.group(1)
    return pakete


def npm_projekt(ordner, rel, tief):
    sw = []
    try:
        pj = json.loads((ordner / 'package.json').read_text())
    except Exception:
        return sw
    direkt = {}
    for feld, dev in (('dependencies', False), ('devDependencies', True), ('optionalDependencies', False)):
        for n, s in (pj.get(feld) or {}).items():
            direkt.setdefault(n, (s, dev))
    lock = {}
    lockdatei = ordner / 'package-lock.json'
    if lockdatei.exists():
        try:
            ld = json.loads(lockdatei.read_text())
            for pfad, info in (ld.get('packages') or {}).items():
                if pfad.startswith('node_modules/') or '/node_modules/' in pfad:
                    lock.setdefault(pfad.split('node_modules/')[-1], info.get('version'))
            for n, info in (ld.get('dependencies') or {}).items():          # lockfileVersion 1
                lock.setdefault(n, info.get('version'))
        except Exception:
            pass
    namen = set(direkt) | (set(lock) if tief else set())
    for n in sorted(namen):
        spez, dev = direkt.get(n, (None, False))
        if lock.get(n):
            v, ungefaehr = lock[n], False
        else:
            v, ungefaehr = ungefaehre_version(spez)
        if v:
            sw.append({'name': n, 'oekosystem': 'npm', 'version': v, 'wo': f'{rel}/package.json',
                       'dev': dev, 'ungefaehr': ungefaehr})
    return sw


def python_projekt(ordner, rel, tief):
    direkt = {}
    for req in sorted(ordner.glob('requirements*.txt')):
        for zeile in req.read_text(errors='replace').splitlines():
            zeile = zeile.split('#')[0].split(';')[0].strip()
            if not zeile or zeile.startswith('-') or '://' in zeile:
                continue
            m = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)', zeile)
            if m:
                direkt.setdefault(pypi_name(m.group(1)), (m.group(3), req.name))
    pp = ordner / 'pyproject.toml'
    if pp.exists():
        text = pp.read_text(errors='replace')
        block = re.search(r'^dependencies\s*=\s*\[(.*?)\]', text, re.S | re.M)
        for s in re.findall(r'"([^"]+)"', block.group(1) if block else ''):
            m = re.match(r'([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)', s)
            if m:
                direkt.setdefault(pypi_name(m.group(1)), (m.group(3).split(';')[0], 'pyproject.toml'))
        poetry = re.search(r'^\[tool\.poetry\.dependencies\]\s*$(.*?)(^\[|\Z)', text, re.S | re.M)
        for n, s in re.findall(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*"([^"]*)"', poetry.group(1) if poetry else '', re.M):
            if n.lower() != 'python':
                direkt.setdefault(pypi_name(n), (s, 'pyproject.toml'))
    lock = {}
    for name in ('uv.lock', 'poetry.lock'):
        if (ordner / name).exists():
            lock.update(toml_pakete((ordner / name).read_text(errors='replace')))
    sw = []
    for n in sorted(set(direkt) | (set(lock) if tief else set())):
        spez, datei = direkt.get(n, (None, 'uv.lock' if (ordner / 'uv.lock').exists() else 'poetry.lock'))
        if lock.get(n):
            v, ungefaehr = lock[n], False
        else:
            v, ungefaehr = ungefaehre_version(spez)
        if v:
            sw.append({'name': n, 'oekosystem': 'PyPI', 'version': v, 'wo': f'{rel}/{datei}', 'ungefaehr': ungefaehr})
    return sw


def composer_projekt(ordner, rel, tief):
    sw = []
    try:
        direkt = {n: s for n, s in (json.loads((ordner / 'composer.json').read_text()).get('require') or {}).items()
                  if '/' in n}
    except Exception:
        direkt = {}
    lock = {}
    if (ordner / 'composer.lock').exists():
        try:
            cl = json.loads((ordner / 'composer.lock').read_text())
            for p in (cl.get('packages') or []) + (cl.get('packages-dev') or []):
                lock[p['name']] = p['version'].lstrip('v')
        except Exception:
            pass
    for n in sorted(set(direkt) | (set(lock) if tief else set())):
        v, ungefaehr = (lock[n], False) if lock.get(n) else ungefaehre_version(direkt.get(n))
        if v:
            sw.append({'name': n, 'oekosystem': 'Packagist', 'version': v, 'wo': f'{rel}/composer.json',
                       'ungefaehr': ungefaehr})
    return sw


def go_projekt(ordner, rel, tief):
    sw = []
    text = (ordner / 'go.mod').read_text(errors='replace')
    for modul, v, rest in re.findall(r'^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/\S+)\s+(v\d\S*)(.*)$', text, re.M):
        if 'indirect' in rest and not tief:
            continue
        sw.append({'name': modul, 'oekosystem': 'Go', 'version': v.lstrip('v'), 'wo': f'{rel}/go.mod'})
    return sw


def image_eintrag(bild, wo):
    """'node:22.23.1-alpine' -> Node 22.23.1; 'n8nio/n8n:1.123.5' -> n8n; andere Images nur für den CISA-Namensabgleich."""
    bild = bild.split('@')[0]
    pfad, _, tag = bild.rpartition(':') if ':' in bild.split('/')[-1] else (bild, '', '')
    name = pfad.split('/')[-1].lower()
    m = re.match(r'v?(\d+(?:\.\d+){0,2})', tag or '')
    v = m.group(1) if m else None
    if '$' in bild:
        return None
    if name in ('node', 'php', 'python'):
        if not v:
            return {'name': name, 'version': tag or 'latest', 'wo': wo, 'unbekannt': True,
                    'hinweis': f'Image-Tag "{tag or "latest"}" ohne Versionsnummer. Feste Version eintragen, sonst weißt du nicht, was läuft.'}
        return {'name': name, 'version': v, 'wo': wo}
    if name == 'n8n':
        if v and v.count('.') == 2:
            return {'name': 'n8n', 'oekosystem': 'npm', 'version': v, 'wo': wo}
        return {'name': 'n8n', 'version': tag or 'latest', 'wo': wo, 'unbekannt': True,
                'hinweis': 'n8n ohne genaue Version im Image-Tag. Version in n8n unter Einstellungen nachsehen.'}
    if name == 'traefik' and v and v.count('.') == 2:
        return {'name': f'github.com/traefik/traefik/v{v.split(".")[0]}', 'anzeige': 'Traefik', 'oekosystem': 'Go',
                'version': v, 'wo': wo}
    return {'name': name, 'version': tag or 'latest', 'wo': wo, 'unbekannt': True, 'nur_name': True,
            'hinweis': 'keine Versionsquelle hinterlegt, nur Abgleich mit der CISA-Liste'}


def docker_projekt(ordner, rel):
    sw = []
    for datei in sorted(list(ordner.glob('Dockerfile*')) + list(ordner.glob('*compose*.y*ml'))):
        text = datei.read_text(errors='replace')
        bilder = re.findall(r'^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', text, re.M | re.I) + \
            re.findall(r'^\s*image:\s*["\']?([^\s"\']+)', text, re.M)
        stufen = set(re.findall(r'^\s*FROM\s+\S+\s+AS\s+(\S+)', text, re.M | re.I))   # Build-Stufen sind keine Images
        for b in bilder:
            if b.lower() in {s.lower() for s in stufen} or b == 'scratch':
                continue
            e = image_eintrag(b, f'{rel}/{datei.name}')
            if e:
                sw.append(e)
    return sw


def inventar_aus_projekt(wurzeln, tief=False):
    sw = []
    for w in wurzeln:
        wurzel = pathlib.Path(w).expanduser().resolve()
        for ordner, unterordner, dateien in os.walk(wurzel):
            unterordner[:] = [u for u in unterordner if u not in UEBERSPRINGEN and not u.startswith('.')]
            tiefe = len(pathlib.Path(ordner).relative_to(wurzel).parts)
            if tiefe >= 4:
                unterordner[:] = []
            o = pathlib.Path(ordner)
            rel = wurzel.name + ('/' + str(o.relative_to(wurzel)) if o != wurzel else '')
            if 'package.json' in dateien:
                sw += npm_projekt(o, rel, tief)
            if any(d.startswith('requirements') and d.endswith('.txt') for d in dateien) or 'pyproject.toml' in dateien:
                sw += python_projekt(o, rel, tief)
            if 'composer.json' in dateien or 'composer.lock' in dateien:
                sw += composer_projekt(o, rel, tief)
            if 'go.mod' in dateien:
                sw += go_projekt(o, rel, tief)
            sw += docker_projekt(o, rel)
    return {'name': ', '.join(pathlib.Path(w).expanduser().resolve().name for w in wurzeln), 'software': sw}


# ---------------------------------------------------------------- Inventar aus dem Server-Check

def inventar_aus_check(text):
    """Baut ein Inventar aus der Ausgabe von check.sh (Versionen aus Docker-Images und vom Server selbst)."""
    sw = []
    for zeile in text.splitlines():
        m = re.match(r'\s+(\S+) -> (.*)', zeile)
        if m:                                   # Docker-Image-Zeile: "  bild:tag -> NODE_VERSION=22.23.1 ... 1.2.3"
            bild, rest = m.groups()
            umgebung = dict(t.split('=', 1) for t in rest.split() if '=' in t)
            # Das Versions-Label des Images ist ein Wort OHNE "=" (check.sh hängt es hinter die Umgebungsvariablen).
            label = next((t.lstrip('v') for t in reversed(rest.split())
                          if '=' not in t and re.fullmatch(r'v?\d+\.\d+\.\d+\S*', t)), None)
            for key, name in [('NODE_VERSION', 'node'), ('PHP_VERSION', 'php'), ('PYTHON_VERSION', 'python')]:
                if umgebung.get(key):
                    sw.append({'name': name, 'version': umgebung[key], 'wo': f'Image {bild}'})
            if umgebung.get('N8N_VERSION'):
                sw.append({'name': 'n8n', 'oekosystem': 'npm', 'version': umgebung['N8N_VERSION'], 'wo': f'Image {bild}'})
            if label and 'traefik' in bild:
                major = label.split('.')[0]
                sw.append({'name': f'github.com/traefik/traefik/v{major}', 'anzeige': 'Traefik', 'oekosystem': 'Go',
                           'version': label, 'wo': f'Image {bild}'})
            elif label and 'n8n' in bild and not umgebung.get('N8N_VERSION'):   # offizielles n8n-Image hat nur das Label
                sw.append({'name': 'n8n', 'oekosystem': 'npm', 'version': label, 'wo': f'Image {bild}'})
            elif 'n8n' in bild and not umgebung.get('N8N_VERSION'):
                sw.append({'name': 'n8n', 'version': '?', 'wo': f'Image {bild}', 'unbekannt': True})
            elif not umgebung and not label:
                e = image_eintrag(bild, f'Image {bild}')
                if e and e.get('nur_name'):
                    sw.append(e)
            continue
        m = re.match(r'(php|node|n8n|python)=(?:Python )?v?(\d[\w.]*)', zeile)
        if m:
            name, v = m.groups()
            e = {'name': name, 'version': v, 'wo': 'direkt auf dem Server'}
            if name == 'n8n':
                e['oekosystem'] = 'npm'
            sw.append(e)
    return {'name': 'Server', 'software': sw}


# ---------------------------------------------------------------- Aufruf

def wert(args, schalter, standard):
    if schalter in args:
        return args[args.index(schalter) + 1]
    return standard


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help', 'hilfe'):
        sys.exit(__doc__)
    befehl = args[0]
    if befehl == '--aus-check':                       # alte Schreibweise
        args, befehl = ['inventar', '--check'] + args[1:], 'inventar'
    elif befehl.endswith('.json'):                    # alte Schreibweise: fruehwarnung.py inventar.json
        args, befehl = ['pruefen'] + args, 'pruefen'

    if befehl == 'lage':
        print(lage(int(wert(args, '--tage', 30))))
    elif befehl == 'inventar' and '--check' in args:
        print(json.dumps(inventar_aus_check(pathlib.Path(wert(args, '--check', '')).read_text()), indent=1,
                         ensure_ascii=False))
    elif befehl == 'inventar' and '--projekt' in args:
        i = args.index('--projekt') + 1
        ordner = [a for a in args[i:] if not a.startswith('--')]
        print(json.dumps(inventar_aus_projekt(ordner or ['.'], tief='--tief' in args), indent=1, ensure_ascii=False))
    elif befehl == 'pruefen':
        pfad = pathlib.Path(args[1])
        inv = json.loads(pfad.read_text())
        inv['_pfad'] = str(pfad)
        print(pruefen(inv, nur_neu='--neu' in args, tage=int(wert(args, '--tage', 90))))
    else:
        sys.exit(__doc__)
