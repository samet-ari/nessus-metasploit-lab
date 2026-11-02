#!/usr/bin/env python3
"""
nessus_ai_report.py
-------------------
Pour aller plus loin — Projet "Découverte et Exploitation de Vulnérabilités"
La Plateforme_ — Samet ARI

Lit un export Nessus (.nessus, format XML), extrait les vulnérabilités,
les classe par type, et produit un rapport Markdown en français.

Deux modes :
  - SANS clé API  : rapport structuré à partir des données Nessus seules.
  - AVEC clé API  : chaque vulnérabilité est enrichie d'une explication et
                    d'une remédiation rédigées par Claude (Anthropic API).

Le script fonctionne dans les deux cas. L'IA est un bonus, pas une
dépendance : s'il n'y a pas de clé ou pas de SDK, on retombe sur le
mode hors-ligne proprement.

Usage :
    python3 nessus_ai_report.py scan.nessus
    python3 nessus_ai_report.py scan.nessus -o rapport.md --min-severity 3
    ANTHROPIC_API_KEY=sk-...  python3 nessus_ai_report.py scan.nessus --ai
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import date

# --- SDK Anthropic : import optionnel -------------------------------------
# Si le SDK n'est pas installé, le mode IA est simplement désactivé.
try:
    import anthropic  # pip install anthropic
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False

SEVERITY_LABELS = {4: "Critique", 3: "Élevée", 2: "Moyenne", 1: "Faible", 0: "Info"}

# Classification par type de vulnérabilité (le "décrire le type" du TP).
# On associe des mots-clés (famille Nessus ou nom du plugin) à une catégorie.
TYPE_RULES = [
    # L'ordre compte : la première règle qui matche gagne. Les cas les plus
    # spécifiques (backdoor, bind shell) passent avant les plus génériques.
    ("Porte dérobée (backdoor)",      ["backdoor", "porte dérobée", "bind shell",
                                       "root shell", "smiley"]),
    ("Faille cryptographique",        ["openssl", "random number", "weak key", "ssl ",
                                       " tls", "cipher", "certificate", "predictable"]),
    ("Authentification faible",       ["default password", "weak password", "'password'",
                                       "default account", "default credential", "anonymous",
                                       "no password", "unpassworded", "empty password",
                                       "cleartext", "weak credential"]),
    ("Exécution de code à distance",  ["gain a shell", "remote code", "command execution",
                                       "arbitrary code", "arbitrary command", "rce",
                                       "code execution"]),
    ("Service obsolète / non corrigé",["obsolete", "unsupported", "end of life", "deprecated",
                                       "outdated", "end-of-life"]),
    ("Mauvaise configuration",        ["misconfiguration", "default configuration",
                                       "world-readable", "permission", "enabled by default"]),
]


def classify(family: str, plugin_name: str) -> str:
    """Range une vulnérabilité dans une catégorie selon des mots-clés."""
    hay = f"{family} {plugin_name}".lower()
    for label, keywords in TYPE_RULES:
        if any(k in hay for k in keywords):
            return label
    return "Autre / non classé"


def parse_nessus(path: str, min_sev: int):
    """Extrait les findings d'un fichier .nessus. Retourne (meta, findings)."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        sys.exit(f"[ERREUR] Fichier XML invalide : {e}")
    except FileNotFoundError:
        sys.exit(f"[ERREUR] Fichier introuvable : {path}")

    root = tree.getroot()
    findings = []
    hosts = set()

    for host in root.iter("ReportHost"):
        host_name = host.get("name", "inconnu")
        hosts.add(host_name)
        for item in host.iter("ReportItem"):
            try:
                sev = int(item.get("severity", "0"))
            except ValueError:
                sev = 0
            if sev < min_sev:
                continue

            def txt(tag):
                el = item.find(tag)
                return el.text.strip() if el is not None and el.text else ""

            findings.append({
                "host": host_name,
                "severity": sev,
                "plugin_id": item.get("pluginID", ""),
                "plugin_name": item.get("pluginName", ""),
                "family": item.get("pluginFamily", ""),
                "port": item.get("port", "0"),
                "protocol": item.get("protocol", ""),
                "svc": item.get("svc_name", ""),
                "cve": [c.text for c in item.findall("cve") if c.text],
                "cvss": txt("cvss_base_score") or txt("cvss3_base_score"),
                "description": txt("description"),
                "solution": txt("solution"),
                "synopsis": txt("synopsis"),
                "type": classify(item.get("pluginFamily", ""), item.get("pluginName", "")),
            })

    # Dédoublonnage par plugin_id (un même plugin peut toucher plusieurs ports).
    seen = {}
    for f in findings:
        key = (f["plugin_id"], f["host"])
        if key not in seen:
            seen[key] = f
    findings = list(seen.values())
    findings.sort(key=lambda f: (-f["severity"], f["plugin_name"]))

    meta = {"hosts": sorted(hosts), "total": len(findings)}
    return meta, findings


# --- Couche IA (Anthropic) -------------------------------------------------
AI_SYSTEM = (
    "Tu es un analyste en cybersécurité. On te donne une vulnérabilité détectée "
    "par Nessus. Réponds en français simple, en deux parties courtes :\n"
    "EXPLICATION: 2-3 phrases expliquant la faille et son impact concret.\n"
    "REMEDIATION: 1-2 phrases sur la correction prioritaire.\n"
    "Sois factuel, pas de remplissage. N'invente pas de CVE ni de détail absent."
)


def ai_enrich(finding: dict, client, model: str) -> dict | None:
    """Demande à Claude une explication + remédiation. None si échec."""
    cve = ", ".join(finding["cve"]) or "aucun"
    prompt = (
        f"Vulnérabilité : {finding['plugin_name']}\n"
        f"Famille : {finding['family']}\n"
        f"CVE : {cve}\n"
        f"CVSS : {finding['cvss'] or 'n/c'}\n"
        f"Port/service : {finding['port']}/{finding['protocol']} {finding['svc']}\n"
        f"Synopsis Nessus : {finding['synopsis'][:500]}\n"
    )
    try:
        msg = client.messages.create(
            model=model,
            max_tokens=350,
            system=AI_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        expl, remed = text, ""
        if "REMEDIATION" in text.upper():
            # découpe grossière sur le mot-clé
            idx = text.upper().index("REMEDIATION")
            expl = text[:idx]
            remed = text[idx:]
        return {"explication": expl.strip(), "remediation": remed.strip()}
    except Exception as e:
        print(f"  [IA] échec sur {finding['plugin_name']}: {e}", file=sys.stderr)
        return None


def get_ai_client():
    """Retourne (client, model) si l'IA est utilisable, sinon (None, None)."""
    if not _HAS_SDK:
        print("[info] SDK 'anthropic' absent — mode hors-ligne. "
              "Installer : pip install anthropic", file=sys.stderr)
        return None, None
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("[info] ANTHROPIC_API_KEY absente — mode hors-ligne.", file=sys.stderr)
        return None, None
    model = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")
    return anthropic.Anthropic(api_key=key), model


# --- Génération du rapport Markdown ---------------------------------------
def build_report(meta, findings, use_ai, client, model):
    by_sev = defaultdict(int)
    by_type = defaultdict(list)
    for f in findings:
        by_sev[f["severity"]] += 1
        by_type[f["type"]].append(f)

    L = []
    L.append("# Rapport d'analyse de vulnérabilités")
    L.append("")
    L.append(f"*Généré le {date.today().isoformat()} — "
             f"{'avec enrichissement IA (Claude)' if use_ai else 'mode hors-ligne'}*")
    L.append("")
    L.append(f"**Cible(s) :** {', '.join(meta['hosts'])}  ")
    L.append(f"**Vulnérabilités retenues :** {meta['total']}")
    L.append("")

    # Résumé par sévérité
    L.append("## 1. Résumé par sévérité")
    L.append("")
    L.append("| Sévérité | Nombre |")
    L.append("|---|---|")
    for sev in (4, 3, 2, 1, 0):
        if by_sev[sev]:
            L.append(f"| {SEVERITY_LABELS[sev]} | {by_sev[sev]} |")
    L.append("")

    # Répartition par type (le "décrire le type de vulnérabilités" du TP)
    L.append("## 2. Répartition par type de vulnérabilité")
    L.append("")
    L.append("| Type | Nombre |")
    L.append("|---|---|")
    for t in sorted(by_type, key=lambda x: -len(by_type[x])):
        L.append(f"| {t} | {len(by_type[t])} |")
    L.append("")

    # Détail des findings
    L.append("## 3. Détail des vulnérabilités")
    L.append("")
    for f in findings:
        cve = ", ".join(f["cve"]) if f["cve"] else "—"
        L.append(f"### [{SEVERITY_LABELS[f['severity']]}] {f['plugin_name']}")
        L.append("")
        L.append(f"- **Type :** {f['type']}")
        L.append(f"- **Port / service :** {f['port']}/{f['protocol']} {f['svc']}".rstrip())
        L.append(f"- **CVE :** {cve}")
        L.append(f"- **CVSS :** {f['cvss'] or '—'}")
        L.append("")
        if use_ai:
            enr = ai_enrich(f, client, model)
            if enr:
                L.append(enr["explication"])
                L.append("")
                if enr["remediation"]:
                    L.append(f"> {enr['remediation']}")
                    L.append("")
                L.append("")
                continue
        # Mode hors-ligne (ou échec IA) : on utilise les champs Nessus bruts.
        if f["synopsis"]:
            L.append(f"{f['synopsis']}")
            L.append("")
        if f["solution"]:
            L.append(f"> **Solution (Nessus) :** {f['solution']}")
            L.append("")
        L.append("")

    L.append("---")
    L.append("*Rapport généré automatiquement à partir de l'export Nessus. "
             "Les explications enrichies par IA doivent être relues avant diffusion.*")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="Génère un rapport FR à partir d'un export Nessus (.nessus).")
    ap.add_argument("nessus_file", help="Chemin du fichier .nessus (XML)")
    ap.add_argument("-o", "--output", default="rapport_nessus.md", help="Fichier Markdown de sortie")
    ap.add_argument("--min-severity", type=int, default=3,
                    help="Sévérité minimale (0=Info … 4=Critique). Défaut : 3 (Élevée+).")
    ap.add_argument("--ai", action="store_true",
                    help="Active l'enrichissement IA (nécessite SDK + ANTHROPIC_API_KEY).")
    args = ap.parse_args()

    meta, findings = parse_nessus(args.nessus_file, args.min_severity)
    if not findings:
        print("[info] Aucune vulnérabilité au seuil demandé.", file=sys.stderr)

    client, model = (None, None)
    use_ai = False
    if args.ai:
        client, model = get_ai_client()
        use_ai = client is not None
        if use_ai:
            print(f"[info] Enrichissement IA activé (modèle {model}).", file=sys.stderr)

    report = build_report(meta, findings, use_ai, client, model)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"[ok] Rapport écrit : {args.output}  ({meta['total']} vulnérabilités)")


if __name__ == "__main__":
    main()
