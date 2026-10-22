# 🛡️ Wazuh + Groq IA — Intégration SOC

**Intégration de l'intelligence artificielle (Groq / Llama 3.3 70B) dans le SIEM Wazuh**

> Projet POC MAGI — WebRDInfo, Monneren (Moselle)  
> Stagiaire : MOHANED Mohamed Ali — Titre Professionnel AIS Niveau 6, AFPA Pompey  
> Tuteur : Julien Mutzenhardt  

---

## 📋 Description

Ce projet ajoute deux outils d'intelligence artificielle au SIEM **Wazuh 4.14.5** :

| Outil | Fichier | Description |
|-------|---------|-------------|
| **Chatbot SOC** | `groq_web_chatbot.py` | Interface web conversationnelle sur port 8888 |
| **Threat Hunter** | `groq_threat_hunter.py` | Analyse IA en ligne de commande |

Les deux outils utilisent le modèle **Llama 3.3 70B** via l'API **Groq** pour analyser les alertes Wazuh en langage naturel.

---

## 🏗️ Architecture

```
                  ┌─────────────────────────────────┐
                  │   Melchior (172.16.0.1)         │
                  │   Wazuh Manager + SIEM          │
                  │                                  │
                  │  /var/ossec/logs/alerts.json ←──┐│
                  │              ↓                   ││
                  │  groq_web_chatbot.py (port 8888) ││
                  │  groq_threat_hunter.py (CLI)     ││
                  │              ↓                   ││
                  │       API Groq (Internet)        ││
                  │    Llama 3.3 70B Versatile       ││
                  └──────────────┬──────────────────-┘│
                                 │                     │
                  ┌──────────────▼──────────────────┐  │
                  │   Agents Wazuh                  │  │
                  │   Balthasar / Casper / Archiral ├──┘
                  │   → envoient alertes à Melchior │
                  └─────────────────────────────────┘
```

---

## ⚙️ Prérequis

- Python 3.8+
- Wazuh Manager installé (`/var/ossec/`)
- Clé API Groq (gratuite sur [console.groq.com](https://console.groq.com))
- Accès Internet depuis le serveur Wazuh

---

## 🚀 Installation

### 1. Cloner le repository

```bash
git clone https://github.com/VOTRE-USERNAME/wazuh-groq-soc.git
cd wazuh-groq-soc
```

### 2. Installer les dépendances

```bash
pip3 install -r requirements.txt --break-system-packages
```

### 3. Configurer la clé API Groq

```bash
# Créer un fichier de variables d'environnement (NE PAS commiter ce fichier)
echo "export GROQ_API_KEY=gsk_votre_cle_groq_ici" >> ~/.bashrc
source ~/.bashrc
```

> ⚠️ **IMPORTANT** : Ne jamais mettre la clé API directement dans le code source ou la commiter sur GitHub.

### 4. Déployer les fichiers Wazuh

```bash
# Copier les scripts d'intégration
cp groq_web_chatbot.py /var/ossec/integrations/
cp groq_threat_hunter.py /var/ossec/integrations/
chmod +x /var/ossec/integrations/groq_*.py

# Copier l'interface web
mkdir -p /var/ossec/integrations/static
cp static/index.html /var/ossec/integrations/static/

# Permissions
chown -R wazuh:wazuh /var/ossec/integrations/groq_*.py
```

---

## ▶️ Utilisation

### Chatbot SOC (interface web)

```bash
# Démarrage du chatbot
export GROQ_API_KEY=gsk_votre_cle_ici
python3 /var/ossec/integrations/groq_web_chatbot.py
```

Interface accessible sur : **http://172.16.0.1:8888**

#### Démarrage automatique (systemd)

```bash
# Créer le service systemd
cat > /etc/systemd/system/wazuh-groq-chatbot.service << 'EOF'
[Unit]
Description=Wazuh SOC Chatbot (Groq IA)
After=network.target wazuh-manager.service

[Service]
Type=simple
User=root
Environment=GROQ_API_KEY=gsk_REMPLACER_PAR_VOTRE_CLE
ExecStart=/usr/bin/python3 /var/ossec/integrations/groq_web_chatbot.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wazuh-groq-chatbot
systemctl start wazuh-groq-chatbot
systemctl status wazuh-groq-chatbot
```

---

### Threat Hunter (ligne de commande)

```bash
export GROQ_API_KEY=gsk_votre_cle_ici

# Analyser les alertes de niveau >= 7 (défaut)
python3 /var/ossec/integrations/groq_threat_hunter.py

# Analyser les alertes de niveau >= 5
python3 /var/ossec/integrations/groq_threat_hunter.py 5

# Analyser 50 alertes de niveau >= 10
python3 /var/ossec/integrations/groq_threat_hunter.py 10 50

# Sortie JSON (pour intégration dans d'autres outils)
python3 /var/ossec/integrations/groq_threat_hunter.py 7 50 --json
```

#### Automatisation avec cron

```bash
# Rapport quotidien à 8h00
echo "0 8 * * * root export GROQ_API_KEY=gsk_CLE_ICI && python3 /var/ossec/integrations/groq_threat_hunter.py 7 >> /var/log/threat-hunter.log 2>&1" >> /etc/crontab
```

---

## 🔐 Sécurité

### Protection de la clé API

| ✅ À faire | ❌ À ne JAMAIS faire |
|-----------|---------------------|
| Utiliser `export GROQ_API_KEY=...` | Mettre la clé dans le code source |
| Stocker dans `/etc/environment` | Commiter `.env` sur GitHub |
| Utiliser un secret manager | Partager la clé par email/chat |
| Révoquer et renouveler régulièrement | Laisser la clé dans les logs |

### Accès réseau

```bash
# Restreindre l'accès au chatbot (LAN uniquement)
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=172.16.0.0/24 port protocol=tcp port=8888 accept'
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 port protocol=tcp port=8888 drop'
firewall-cmd --reload
```

---

## 📊 Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `GROQ_API_KEY` | *(obligatoire)* | Clé API Groq |
| `WAZUH_ALERTS_PATH` | `/var/ossec/logs/alerts/alerts.json` | Chemin des alertes |
| `WAZUH_STATIC_PATH` | `/var/ossec/integrations/static` | Dossier interface web |
| `CHATBOT_HOST` | `172.16.0.1` | IP d'écoute du chatbot |
| `CHATBOT_PORT` | `8888` | Port d'écoute du chatbot |

---

## 🔌 API Endpoints

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/` | GET | Interface web du chatbot |
| `/chat` | POST | Envoi d'un message au chatbot |
| `/health` | GET | Vérification de l'état du service |

### Exemple d'appel API

```bash
curl -X POST http://172.16.0.1:8888/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Analyse les dernières alertes Wazuh", "session_id": "test123"}'
```

---

## 🧰 Intégration dans le projet MAGI

Ce composant s'intègre dans l'architecture SOC complète :

- **Wazuh SIEM** : collecte et corrélation des alertes
- **OpenSearch** : stockage et indexation des logs
- **Groq Chatbot** : analyse conversationnelle (ce projet)
- **Ollama** : Threat Hunting local (LAN, sans internet)
- **Google Gemini** : enrichissement CVE via intégration native Wazuh

---

## 📄 Licence

Projet réalisé dans le cadre du Titre Professionnel AIS Niveau 6 — AFPA Pompey.  
Usage pédagogique et professionnel.

---

*Stagiaire : MOHANED Mohamed Ali | Tuteur : Julien Mutzenhardt | WebRDInfo, Monneren (57)*
