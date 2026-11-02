# Pour aller plus loin — Générateur de rapport Nessus assisté par IA

Extension personnelle du projet **« Découverte et Exploitation de Vulnérabilités »**
(La Plateforme_). Automatise ce que j'ai fait à la main au Job 04 : lire les
résultats Nessus, les classer par type, et rédiger un rapport.

## Ce que fait l'outil

1. Lit un export Nessus `.nessus` (format XML).
2. Extrait les vulnérabilités, les dédoublonne, les classe par type
   (porte dérobée, RCE, auth faible, cryptographique, obsolète…).
3. Produit un **rapport Markdown en français** : résumé par sévérité,
   répartition par type, détail de chaque faille.
4. **En option** : enrichit chaque vulnérabilité avec une explication et une
   remédiation rédigées par **Claude (API Anthropic)**.

## Les deux modes (honnête sur les dépendances)

| Mode | Dépendances | Résultat |
|---|---|---|
| **Hors-ligne** (défaut) | Python 3 seul | Rapport à partir des données Nessus (synopsis + solution Nessus) |
| **IA** (`--ai`) | `pip install anthropic` + `ANTHROPIC_API_KEY` | Explications et remédiations générées par Claude |

Si le SDK ou la clé manquent, le mode `--ai` **retombe proprement en
hors-ligne** — le script ne plante jamais pour ça.

## Utilisation

```bash
# Mode hors-ligne, vulnérabilités Élevée et plus (défaut)
python3 nessus_ai_report.py scan.nessus -o rapport.md

# Inclure les Moyennes aussi (seuil = 2)
python3 nessus_ai_report.py scan.nessus --min-severity 2

# Mode IA (nécessite la clé)
pip install anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
python3 nessus_ai_report.py scan.nessus --ai -o rapport_ia.md
```

Seuils de sévérité : `0`=Info, `1`=Faible, `2`=Moyenne, `3`=Élevée, `4`=Critique.

## Obtenir le fichier `.nessus`

Dans l'interface Nessus : ouvrir le scan → bouton **Export** → format
**Nessus** (`.nessus`). C'est un fichier XML ; c'est l'entrée de cet outil.

## Coût (mode IA)

Chaque vulnérabilité = un appel API court (~350 tokens de sortie). Pour un
scan Metasploitable 2 (une dizaine de findings au seuil Élevée+), le coût est
de l'ordre de quelques centimes. À surveiller si on scanne un parc entier.

## Limites (assumées)

- La **classification par type** repose sur des mots-clés : elle est rapide
  mais approximative. Une faille peut tomber dans une catégorie voisine
  (ex. une clé SSH faible classée « RCE » car sa famille Nessus est
  « Gain a shell remotely »). Le rapport le signale : **les résultats IA et la
  classification doivent être relus par un humain avant diffusion.**
- L'IA **n'invente pas** de CVE ni de détail : elle reformule ce que Nessus a
  déjà fourni. Elle n'est pas une source de vérité, c'est un rédacteur.
- Pas de données sensibles stockées : le script ne lit que le `.nessus` fourni.

## Pourquoi ce projet

Il montre la suite logique d'un scan : passer d'une liste brute de 72 lignes
Nessus à un rapport lisible et priorisé, et automatiser la partie rédaction.
L'IA est utilisée comme **outil d'accélération**, encadré par une relecture
humaine — pas comme une boîte noire.
