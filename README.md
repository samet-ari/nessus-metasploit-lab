# Découverte et Exploitation de Vulnérabilités — Nessus & Metasploit

Projet scolaire de cybersécurité réalisé à **La Plateforme_** (Marseille).
Chaîne offensive complète dans un laboratoire **isolé**, de la détection à la
remédiation, avec une extension personnelle assistée par IA.

> ⚠️ **Cadre légal et éthique** — Toutes les manipulations ont été réalisées
> sur une machine volontairement vulnérable (**Metasploitable 2**), dans un
> réseau isolé, à des fins **pédagogiques**. Aucun système tiers n'a été ciblé.

---

## Le projet en bref

| Étape | Outil | Résultat |
|---|---|---|
| Scan de vulnérabilités | Nessus Essentials | 9 vulnérabilités critiques |
| Analyse & classification | — | Par type (backdoor, RCE, auth faible, crypto…) |
| Exploitation | Metasploit + `vncviewer` | **Accès root par deux vecteurs** |
| Remédiation | — | Corrections par faille + priorisation |
| Pour aller plus loin | Python + API Claude | Générateur de rapport automatisé |

**Laboratoire :** Kali Linux (attaquant, `192.168.47.132`) → Metasploitable 2
(cible, `192.168.47.133`), réseau NAT isolé `192.168.47.0/24`.

**Deux vecteurs d'accès root démontrés :**
- **UnrealIRCd backdoor** (CVE-2010-2075) — *porte dérobée / RCE* — via Metasploit.
- **VNC 'password'** (port 5900) — *authentification faible* — via `vncviewer`.

---

## Contenu du dépôt

```
docs/         Rapports (Markdown + PDF)
              ├─ Job05-06  Exploitation & post-exploitation
              └─ Job07     Remédiation et recommandations
presentation/ Support de présentation (.pptx)
tool/         "Pour aller plus loin" — générateur de rapport Nessus assisté par IA
```

### `tool/` — Générateur de rapport assisté par IA

Automatise la phase d'analyse : lit un export Nessus `.nessus`, classe les
vulnérabilités par type, et produit un rapport Markdown en français. En option,
enrichit chaque faille avec une explication rédigée par **Claude (API
Anthropic)**. Fonctionne aussi **sans clé API** (mode hors-ligne).

```bash
python3 tool/nessus_ai_report.py tool/scan_metasploitable.nessus -o rapport.md
```

Voir [`tool/README.md`](tool/README.md) pour les détails et le mode IA.

---

## Compétences mises en œuvre

Scan de vulnérabilités · analyse de CVE · exploitation (Metasploit) ·
post-exploitation · remédiation · scripting Python · intégration d'API LLM.

---

*Auteur : Samet ARI — Étudiant en cybersécurité, La Plateforme_ (Marseille).*
