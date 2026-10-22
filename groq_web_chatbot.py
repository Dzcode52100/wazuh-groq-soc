#!/usr/bin/env python3
"""
==============================================================
Wazuh SOC Chatbot — Intégration Groq IA
Projet POC MAGI — WebRDInfo (Monneren, Moselle)
Stagiaire : MOHANED Mohamed Ali — AIS Niveau 6 AFPA Pompey
Tuteur    : Julien Mutzenhardt
==============================================================

Chatbot conversationnel SOC intégré au Wazuh Dashboard.
- Modèle : Llama 3.3 70B via API Groq
- Lecture des alertes Wazuh en temps réel (alerts.json)
- Interface web accessible sur http://172.16.0.1:8888
- Historique de conversation par session

SÉCURITÉ : Ne jamais mettre la clé API en dur dans ce fichier.
Utiliser la variable d'environnement GROQ_API_KEY :
    export GROQ_API_KEY=gsk_votre_cle_ici
    python3 groq_web_chatbot.py
"""

import json
import os
from flask import Flask, request, jsonify
from groq import Groq

# === Configuration ===
# Clé API lue depuis la variable d'environnement (OBLIGATOIRE)
API_KEY = os.environ.get('GROQ_API_KEY')
if not API_KEY:
    raise EnvironmentError(
        "Variable d'environnement GROQ_API_KEY manquante.\n"
        "Exécutez : export GROQ_API_KEY=gsk_votre_cle_ici"
    )

# Chemin des fichiers Wazuh (adapter si installation non standard)
WAZUH_ALERTS_PATH = os.environ.get(
    'WAZUH_ALERTS_PATH',
    '/var/ossec/logs/alerts/alerts.json'
)
WAZUH_STATIC_PATH = os.environ.get(
    'WAZUH_STATIC_PATH',
    '/var/ossec/integrations/static'
)

# Port d'écoute
SERVER_HOST = os.environ.get('CHATBOT_HOST', '172.16.0.1')
SERVER_PORT = int(os.environ.get('CHATBOT_PORT', '8888'))

# Modèle Groq utilisé
GROQ_MODEL = "llama-3.3-70b-versatile"

# Initialisation du client Groq
client = Groq(api_key=API_KEY)

# Application Flask
app = Flask(__name__, static_folder=WAZUH_STATIC_PATH)

# Historiques de conversation par session
historiques = {}

# Prompt système : rôle de l'assistant SOC
SYSTEM_PROMPT = (
    "Tu es un assistant SOC (Security Operations Center) expert, "
    "intégré au SIEM Wazuh du POC MAGI chez WebRDInfo. "
    "Tu analyses les alertes de sécurité, identifies les menaces "
    "et proposes des actions correctives. "
    "Reponds toujours en français. "
    "Sois concis, précis et professionnel."
)

# Mots-clés déclenchant la lecture des alertes Wazuh
MOTS_CLES_ALERTES = [
    'alerte', 'securite', 'menace', 'analyse', 'resume',
    'brute', 'ssh', 'attaque', 'suricata', 'incident',
    'intrusion', 'anomalie', 'detection', 'log', 'event'
]


def charger_alertes(niveau_min=3, nb_max=10):
    """
    Charge les dernières alertes Wazuh depuis alerts.json.
    Filtre par niveau de sévérité (>= niveau_min).
    Retourne une liste de chaînes formatées.
    """
    alertes = []
    try:
        with open(WAZUH_ALERTS_PATH, 'r') as f:
            lignes = f.readlines()[-500:]  # Dernières 500 lignes
        for ligne in reversed(lignes):
            try:
                a = json.loads(ligne.strip())
                niveau = a.get('rule', {}).get('level', 0)
                if niveau >= niveau_min:
                    agent = a.get('agent', {}).get('name', 'inconnu')
                    description = a.get('rule', {}).get('description', 'N/A')
                    timestamp = a.get('timestamp', '')[:19]
                    alertes.append(
                        f"[{timestamp}] Niveau {niveau} | Agent: {agent} | {description}"
                    )
                    if len(alertes) >= nb_max:
                        break
            except (json.JSONDecodeError, KeyError):
                continue
    except FileNotFoundError:
        pass
    except PermissionError:
        return ['[ERREUR] Permission refusée pour lire alerts.json']
    return alertes


@app.route('/')
def index():
    """Sert l'interface web du chatbot."""
    html_path = os.path.join(WAZUH_STATIC_PATH, 'index.html')
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return (
            "<h1>Wazuh SOC Chatbot</h1>"
            "<p>Fichier index.html introuvable dans : " + html_path + "</p>"
        ), 404


@app.route('/chat', methods=['POST'])
def chat():
    """
    Endpoint principal du chatbot.
    Reçoit un message JSON : {message, session_id}
    Retourne : {response}
    """
    try:
        data = request.json
        if not data:
            return jsonify({'response': 'Requête invalide'}), 400

        message = data.get('message', '').strip()
        sid = data.get('session_id', 'default')

        if not message:
            return jsonify({'response': 'Message vide'}), 400

        # Initialiser l'historique de la session
        if sid not in historiques:
            historiques[sid] = [{'role': 'system', 'content': SYSTEM_PROMPT}]

        # Enrichir le message avec les alertes Wazuh si pertinent
        message_final = message
        if any(mot in message.lower() for mot in MOTS_CLES_ALERTES):
            alertes = charger_alertes(niveau_min=3, nb_max=10)
            if alertes:
                contexte = '\n'.join(alertes)
                message_final = (
                    f"{message}\n\n"
                    f"=== Alertes Wazuh récentes ===\n{contexte}"
                )

        # Ajouter le message à l'historique
        historiques[sid].append({'role': 'user', 'content': message_final})

        # Limiter l'historique à 20 échanges (+ prompt système)
        if len(historiques[sid]) > 22:
            historiques[sid] = (
                [historiques[sid][0]] + historiques[sid][-20:]
            )

        # Appel à l'API Groq
        reponse = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=historiques[sid],
            max_tokens=1000,
            temperature=0.7
        )

        texte_reponse = reponse.choices[0].message.content

        # Sauvegarder la réponse dans l'historique
        historiques[sid].append({'role': 'assistant', 'content': texte_reponse})

        return jsonify({'response': texte_reponse})

    except Exception as e:
        return jsonify({'response': f'Erreur serveur: {str(e)}'}), 500


@app.route('/health')
def health():
    """Endpoint de vérification de santé."""
    return jsonify({
        'status': 'ok',
        'model': GROQ_MODEL,
        'sessions': len(historiques)
    })


if __name__ == '__main__':
    print(f"=== Wazuh SOC Chatbot (Groq IA) ===")
    print(f"Modèle    : {GROQ_MODEL}")
    print(f"Écoute    : http://{SERVER_HOST}:{SERVER_PORT}")
    print(f"Alertes   : {WAZUH_ALERTS_PATH}")
    print(f"Interface : http://{SERVER_HOST}:{SERVER_PORT}/")
    print("(Ctrl+C pour arrêter)")
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=False)
