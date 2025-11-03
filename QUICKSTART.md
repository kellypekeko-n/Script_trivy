# 🚀 Guide de Démarrage Rapide

## Installation en 3 étapes

### 1️⃣ Installer les dépendances

```powershell
pip install -r requirements.txt
```

### 2️⃣ Configurer la clé API NVD (optionnel mais recommandé)

```powershell
$env:NVD_API_KEY="votre_cle_api"
```

💡 **Obtenez une clé gratuite** : https://nvd.nist.gov/developers/request-an-api-key

### 3️⃣ Lancer l'analyse

#### Option A : Avec l'exemple fourni
```powershell
# Utiliser le fichier exemple
$env:TRIVY_REPORT="exemple_rapport_trivy.json"
python main.py
```

#### Option B : Avec votre propre rapport Trivy
```powershell
# Générer un rapport Trivy
trivy image -f json -o rapport_vulnerabilites.json nginx:latest

# Lancer l'analyse
python main.py
```

#### Option C : Script automatique (Windows)
```powershell
.\run_example.ps1
```

---

## 📊 Résultats

Les rapports sont générés dans le dossier **`output/`** :

| Fichier | Description |
|---------|-------------|
| 📄 `rapport_vulnerabilites_*.csv` | Données tabulaires complètes |
| 📄 `rapport_vulnerabilites_*.pdf` | Rapport professionnel avec graphiques |
| 📊 `visualisations_*.png` | Graphiques de distribution |
| 📝 `trivy_analysis.log` | Logs détaillés de l'analyse |

---

## ⚙️ Configuration Rapide

Créez un fichier `.env` à partir de `.env.example` :

```powershell
Copy-Item .env.example .env
# Puis éditez .env avec vos valeurs
```

---

## 🔍 Exemples de Commandes Trivy

### Scanner une image Docker
```bash
trivy image -f json -o rapport.json nginx:latest
trivy image -f json -o rapport.json python:3.11-slim
trivy image -f json -o rapport.json alpine:latest
```

### Scanner un projet local
```bash
trivy fs -f json -o rapport.json .
trivy fs -f json -o rapport.json /chemin/vers/projet
```

### Scanner un dépôt Git
```bash
trivy repo -f json -o rapport.json https://github.com/user/repo
```

### Scanner un cluster Kubernetes
```bash
trivy k8s -f json -o rapport.json cluster
trivy k8s -f json -o rapport.json --namespace default
```

---

## 🎯 Cas d'Usage Courants

### 1. Audit de sécurité d'une image Docker

```powershell
# Scanner l'image
trivy image -f json -o rapport.json myapp:latest

# Analyser avec NVD
$env:NVD_API_KEY="votre_cle"
python main.py

# Consulter le PDF
start output\rapport_vulnerabilites_*.pdf
```

### 2. Analyse CI/CD automatisée

```yaml
# .github/workflows/security-scan.yml
- name: Run Trivy
  run: trivy image -f json -o rapport.json ${{ env.IMAGE_NAME }}

- name: Analyze with NVD
  env:
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
  run: python main.py

- name: Upload reports
  uses: actions/upload-artifact@v3
  with:
    name: security-reports
    path: output/
```

### 3. Filtrer par sévérité

Modifiez `config.py` :

```python
# Analyser uniquement les vulnérabilités HIGH et CRITICAL
min_severity: Optional[str] = "HIGH"
```

### 4. Analyse rapide (test)

```python
# Limiter à 10 CVE pour tester
max_cves_to_process: Optional[int] = 10
```

---

## 🐛 Résolution de Problèmes

### Problème : "Module not found"
```powershell
pip install --upgrade -r requirements.txt
```

### Problème : "Fichier Trivy introuvable"
```powershell
# Vérifier le chemin
$env:TRIVY_REPORT="chemin/complet/vers/rapport.json"
```

### Problème : "Rate limit exceeded"
```powershell
# Utiliser une clé API
$env:NVD_API_KEY="votre_cle"
```

### Problème : Analyse trop lente
```python
# Dans config.py, limiter le nombre de CVE
max_cves_to_process: Optional[int] = 50
```

---

## 📚 Prochaines Étapes

1. ✅ Consultez le **README.md** pour la documentation complète
2. 🔧 Personnalisez **config.py** selon vos besoins
3. 📊 Explorez les rapports générés dans **output/**
4. 🔄 Intégrez dans votre pipeline CI/CD

---

## 💡 Astuces

- **Performance** : Utilisez toujours une clé API NVD (100 req/min vs 10)
- **Filtrage** : Configurez `min_severity` pour ignorer les vulnérabilités LOW
- **Logs** : Consultez `trivy_analysis.log` en cas de problème
- **Automatisation** : Utilisez `run_example.ps1` pour des analyses répétées

---

**Besoin d'aide ?** Consultez le README.md ou les logs !
