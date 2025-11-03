# 🛡️ Analyseur de Vulnérabilités Trivy + NVD

Script Python professionnel pour analyser les rapports de vulnérabilités générés par **Trivy** et les enrichir avec les données de la **National Vulnerability Database (NVD)**.

## 📋 Fonctionnalités

- ✅ **Parsing automatique** des rapports JSON Trivy
- 🔍 **Enrichissement** avec l'API NVD (scores CVSS, CWE, descriptions)
- 📊 **Visualisations** : graphiques de distribution des vulnérabilités
- 📄 **Rapports multiples** : CSV et PDF professionnels
- ⚙️ **Configuration flexible** via variables d'environnement
- 🚦 **Rate limiting** intelligent (avec/sans clé API)
- 📝 **Logging complet** pour le suivi des opérations

## 🏗️ Architecture Modulaire

```
Script_trivy/
├── main.py                  # Point d'entrée principal
├── config.py                # Configuration et constantes
├── trivy_parser.py          # Parser des rapports Trivy
├── nvd_client.py            # Client API NVD
├── report_generator.py      # Génération de rapports
├── requirements.txt         # Dépendances Python
├── README.md               # Documentation
└── output/                 # Répertoire de sortie (créé automatiquement)
```

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- Trivy installé ([guide d'installation](https://aquasecurity.github.io/trivy/latest/getting-started/installation/))

### Installation des dépendances

```bash
pip install -r requirements.txt
```

## 🔑 Configuration

### 1. Obtenir une clé API NVD (recommandé)

Obtenez une clé API gratuite sur : https://nvd.nist.gov/developers/request-an-api-key

**Avantages avec clé API :**
- 100 requêtes/minute (vs 10 sans clé)
- Analyse plus rapide
- Moins de timeouts

### 2. Définir les variables d'environnement

#### Windows (PowerShell)
```powershell
$env:NVD_API_KEY="votre_cle_api_ici"
$env:TRIVY_REPORT="rapport_vulnerabilites.json"
$env:OUTPUT_DIR="output"
```

#### Linux/Mac
```bash
export NVD_API_KEY="votre_cle_api_ici"
export TRIVY_REPORT="rapport_vulnerabilites.json"
export OUTPUT_DIR="output"
```

## 📖 Utilisation

### Étape 1 : Générer un rapport Trivy

#### Scanner une image Docker
```bash
trivy image -f json -o rapport_vulnerabilites.json nginx:latest
```

#### Scanner un système de fichiers
```bash
trivy fs -f json -o rapport_vulnerabilites.json /chemin/vers/projet
```

#### Scanner un cluster Kubernetes
```bash
trivy k8s -f json -o rapport_vulnerabilites.json cluster
```

### Étape 2 : Exécuter l'analyse

```bash
python main.py
```

## 📊 Sorties Générées

Le script génère automatiquement dans le dossier `output/` :

1. **Rapport CSV** : `rapport_vulnerabilites_YYYYMMDD_HHMMSS.csv`
   - Toutes les CVE avec données Trivy + NVD
   - Format tabulaire pour analyse Excel/Pandas

2. **Rapport PDF** : `rapport_vulnerabilites_YYYYMMDD_HHMMSS.pdf`
   - Résumé exécutif
   - Visualisations intégrées
   - Top 20 des vulnérabilités critiques

3. **Visualisations** : `visualisations_YYYYMMDD_HHMMSS.png`
   - Répartition par sévérité
   - Distribution des scores CVSS
   - Top 10 des packages vulnérables
   - Top 10 des types de faiblesses (CWE)

4. **Logs** : `trivy_analysis.log`
   - Historique complet des opérations

## ⚙️ Configuration Avancée

Modifiez `config.py` pour personnaliser :

```python
@dataclass
class Config:
    # Filtrer par sévérité minimale
    min_severity: Optional[str] = "MEDIUM"  # None, "LOW", "MEDIUM", "HIGH", "CRITICAL"
    
    # Limiter le nombre de CVE à traiter (pour tests)
    max_cves_to_process: Optional[int] = 50
    
    # Désactiver certains rapports
    generate_csv: bool = True
    generate_pdf: bool = True
    generate_visualizations: bool = True
    
    # Ajuster le rate limiting
    rate_limit_delay: float = 0.6  # secondes entre requêtes
```

## 📝 Exemple de Workflow Complet

```bash
# 1. Scanner une image Docker
trivy image -f json -o rapport_vulnerabilites.json alpine:latest

# 2. Définir la clé API
$env:NVD_API_KEY="votre_cle_api"

# 3. Lancer l'analyse
python main.py

# 4. Consulter les résultats
cd output
# Ouvrir le PDF ou le CSV généré
```

## 🔧 Dépannage

### Erreur : "Fichier Trivy introuvable"
- Vérifiez que `rapport_vulnerabilites.json` existe dans le répertoire courant
- Ou définissez `TRIVY_REPORT` avec le chemin complet

### Erreur : "Accès refusé - Vérifiez votre clé API"
- Vérifiez que votre clé API NVD est valide
- Attendez quelques minutes après la création de la clé

### Timeouts fréquents
- Réduisez `max_cves_to_process` dans `config.py`
- Augmentez `request_timeout` dans `config.py`
- Vérifiez votre connexion internet

### Erreurs d'import
```bash
pip install --upgrade -r requirements.txt
```

## 📚 Structure des Données

### Colonnes du rapport CSV

| Colonne | Source | Description |
|---------|--------|-------------|
| `cve_id` | Trivy | Identifiant CVE |
| `severity` | Trivy | Sévérité (CRITICAL, HIGH, MEDIUM, LOW) |
| `pkg_name` | Trivy | Nom du package vulnérable |
| `installed_version` | Trivy | Version installée |
| `fixed_version` | Trivy | Version corrigée |
| `cvss_score` | NVD | Score CVSS (0-10) |
| `cvss_severity` | NVD | Sévérité CVSS |
| `cvss_vector` | NVD | Vecteur d'attaque CVSS |
| `cwe_ids` | NVD | Types de faiblesses (CWE-XX) |
| `description_nvd` | NVD | Description détaillée |
| `published_date` | NVD | Date de publication |
| `last_modified_date` | NVD | Dernière modification |

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Ajouter de nouvelles fonctionnalités

## 📄 Licence

Ce projet est sous licence MIT.

## 👤 Auteur

**Kelly Pekeko**

## 🔗 Ressources

- [Documentation Trivy](https://aquasecurity.github.io/trivy/)
- [API NVD](https://nvd.nist.gov/developers)
- [Base de données CVE](https://cve.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)

---

**Note** : Ce script est fourni à des fins éducatives et de sécurité. Utilisez-le de manière responsable.
