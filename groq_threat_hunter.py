#!/usr/bin/env python3
"""
==============================================================
Wazuh Threat Hunter — Analyse IA en ligne de commande
Projet POC MAGI — WebRDInfo (Monneren, Moselle)
Stagiaire : MOHANED Mohamed Ali — AIS Niveau 6 AFPA Pompey
Tuteur    : Julien Mutzenhardt
==============================================================

Script d'analyse de menaces par IA (Groq/Llama 3.3 70B).
Lit les alertes Wazuh, filtre par niveau, envoie à Groq
pour une analyse de threat hunting en langage naturel.

Usage :
    python3 groq_threat_hunter.py              # Niveau >= 7 (défaut)
    python3 groq_threat_hunter.py 5            # Niveau >= 5
    python3 groq_threat_hunter.py 10 20        # Niveau >= 10, max 20 alertes
    python3 groq_threat_hunter.py 7 50 --json  # Sortie JSON

Variables d'environnement requises :
    export GROQ_API_KEY=gsk_votre_cle_ici
"""

import json
import os
import sys
from datetime import datetime
from groq import Groq

# === Configuration ===
API_KEY = os.environ.get('GROQ_API_KEY')
if not API_KEY:
    print("[ERREUR] Variable GROQ_API_KEY manquante.")
    print("Exécutez : export GROQ_API_KEY=gsk_votre_cle_ici")
    sys.exit(1)

WAZUH_ALERTS_PATH = os.environ.get(
    'WAZUH_ALERTS_PATH',
    '/var/ossec/logs/alerts/alerts.json'
)

GROQ_MODEL = "llama-3.3-70b-versatile"

client = Groq(api_key=API_KEY)


def charger_alertes(niveau_min=7, nb_max=50):
    """
    Charge les alertes Wazuh filtrées par niveau de sévérité.
    Retourne une liste de dictionnaires d'alertes.
    """
    alertes = []
    try:
        with open(WAZUH_ALERTS_PATH, 'r') as f:
            lignes = f.readlines()[-1000:]  # Dernières 1000 lignes
        for ligne in reversed(lignes):
            try:
                a = json.loads(ligne.strip())
                niveau = a.get('rule', {}).get('level', 0)
                if niveau >= niveau_min:
                    alertes.append({
                        'timestamp': a.get('timestamp', '')[:19],
                        'niveau': niveau,
                        'agent': a.get('agent', {}).get('name', 'inconnu'),
                        'ip': a.get('agent', {}).get('ip', 'N/A'),
                        'rule_id': a.get('rule', {}).get('id', 'N/A'),
                        'description': a.get('rule', {}).get('description', 'N/A'),
                        'mitre': a.get('rule', {}).get('mitre', {}).get('id', []),
                        'src_ip': a.get('data', {}).get('srcip', 'N/A'),
                    })
                    if len(alertes) >= nb_max:
                        break
            except (json.JSONDecodeError, KeyError):
                continue
    except FileNotFoundError:
        print(f"[ERREUR] Fichier introuvable : {WAZUH_ALERTS_PATH}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERREUR] Permission refusée : {WAZUH_ALERTS_PATH}")
        sys.exit(1)
    return alertes


def formater_alertes_texte(alertes):
    """Formate les alertes en texte lisible pour le modèle IA."""
    if not alertes:
        return "Aucune alerte trouvée pour ce niveau de sévérité."
    lignes = []
    for i, a in enumerate(alertes, 1):
        mitre = ', '.join(a['mitre']) if a['mitre'] else 'N/A'
        lignes.append(
            f"{i}. [{a['timestamp']}] Niv.{a['niveau']} | "
            f"Agent: {a['agent']} ({a['ip']}) | "
            f"Règle: {a['rule_id']} | "
            f"{a['description']} | "
            f"Src: {a['src_ip']} | "
            f"MITRE: {mitre}"
        )
    return '\n'.join(lignes)


def analyser_avec_groq(alertes_texte, niveau_min, nb_alertes):
    """
    Envoie les alertes à l'API Groq pour analyse de threat hunting.
    Retourne le texte de l'analyse.
    """
    prompt_systeme = (
        "Tu es un analyste SOC (Security Operations Center) expert en threat hunting. "
        "Tu travailles sur le SIEM Wazuh du POC MAGI chez WebRDInfo. "
        "Ton rôle : analyser les alertes de sécurité, identifier les schémas d'attaque, "
        "classifier les menaces selon MITRE ATT&CK, et proposer des actions correctives. "
        "Sois précis, structuré et professionnel. Réponds en français."
    )

    prompt_utilisateur = (
        f"Analyse de Threat Hunting — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"Niveau de sévérité minimum : {niveau_min}\n"
        f"Nombre d'alertes analysées : {nb_alertes}\n\n"
        f"=== ALERTES WAZUH ===\n{alertes_texte}\n\n"
        f"=== DEMANDE D'ANALYSE ===\n"
        f"1. Résumé des menaces détectées\n"
        f"2. Classification MITRE ATT&CK\n"
        f"3. Agents les plus ciblés\n"
        f"4. Indicateurs de compromission (IOC)\n"
        f"5. Actions correctives recommandées\n"
        f"6. Niveau de risque global (Critique/Élevé/Moyen/Faible)"
    )

    reponse = client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {'role': 'system', 'content': prompt_systeme},
            {'role': 'user', 'content': prompt_utilisateur}
        ],
        max_tokens=2000,
        temperature=0.3  # Plus déterministe pour l'analyse de sécurité
    )

    return reponse.choices[0].message.content


def afficher_rapport(analyse, alertes, sortie_json=False):
    """Affiche le rapport d'analyse."""
    if sortie_json:
        rapport = {
            'timestamp': datetime.now().isoformat(),
            'nb_alertes': len(alertes),
            'modele': GROQ_MODEL,
            'analyse': analyse,
            'alertes': alertes
        }
        print(json.dumps(rapport, ensure_ascii=False, indent=2))
    else:
        print("\n" + "="*60)
        print("   RAPPORT THREAT HUNTING — WAZUH SOC (Groq IA)")
        print("="*60)
        print(f"Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Alertes   : {len(alertes)} analysées")
        print(f"Modèle    : {GROQ_MODEL}")
        print("="*60 + "\n")
        print(analyse)
        print("\n" + "="*60)


def main():
    """Point d'entrée principal."""
    # Parsing des arguments
    args = sys.argv[1:]
    sortie_json = '--json' in args
    args = [a for a in args if not a.startswith('--')]

    niveau_min = int(args[0]) if len(args) >= 1 else 7
    nb_max = int(args[1]) if len(args) >= 2 else 50

    # Validation
    if not (1 <= niveau_min <= 15):
        print("[ERREUR] Niveau doit être entre 1 et 15")
        sys.exit(1)
    if not (1 <= nb_max <= 200):
        print("[ERREUR] Nombre d'alertes max doit être entre 1 et 200")
        sys.exit(1)

    if not sortie_json:
        print(f"[*] Chargement des alertes Wazuh (niveau >= {niveau_min})...")

    # Chargement des alertes
    alertes = charger_alertes(niveau_min=niveau_min, nb_max=nb_max)

    if not alertes:
        print(f"[INFO] Aucune alerte de niveau >= {niveau_min} trouvée.")
        sys.exit(0)

    if not sortie_json:
        print(f"[*] {len(alertes)} alertes trouvées. Analyse en cours...")

    # Formatage et analyse IA
    alertes_texte = formater_alertes_texte(alertes)
    analyse = analyser_avec_groq(alertes_texte, niveau_min, len(alertes))

    # Affichage du rapport
    afficher_rapport(analyse, alertes, sortie_json)


if __name__ == '__main__':
    main()
