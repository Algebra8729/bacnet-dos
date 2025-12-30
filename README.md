# BACnet-DoS & Industrial Security Audit 🛡️

Ce projet est une **Preuve de Concept (PoC)** développée pour auditer la résilience des réseaux de **Gestion Technique du Bâtiment (GTB)**, spécifiquement sur le protocole **BACnet/IP (ASHRAE 135)**.

## 📋 Contexte technique
Cet outil permet de simuler des vecteurs d'attaque pour tester les barrières de sécurité (segmentation, IDS).

## 🚀 Fonctionnalités
- **Discovery (scan)** : Mapping automatique des automates présents sur le segment réseau via trames Who-Is.
- **Manipulation (write)** : Injection de trames WriteProperty avec encodage **IEEE 754 (Float 32-bit)** pour modifier les consignes physiques.
- **Déni de Service (flood)** : Injection haute fréquence en **Priorité 1** (la plus haute en BACnet) pour verrouiller un équipement et bloquer la supervision légitime.
- **Restaurateur (relinquish)** : Libération des slots de priorité pour rendre le contrôle aux systèmes officiels.

## 🛠️ Utilisation
### Discovery
```bash
python app.py --iface eth0 scan --range 192.168.1.255
```

### Envoi d'une commande
```bash
python app.py --iface eth0 flood --target "Insert ip" --inst 1 --val 100.0
```

### Restauration du service
```bash
python app.py --iface eth0 relinquish --target "Insert ip" --inst 1
```

### ⚠️ Disclaimer
Cet outil est destiné à un usage éducatif et professionnel uniquement. L'auteur décline toute responsabilité en cas d'usage malveillant sur des infrastructures de production.
For Educational and Professional Audit Purposes Only
