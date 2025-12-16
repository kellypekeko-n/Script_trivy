# Analyseur Trivy + NVD

Script Python pour analyser des cibles, générer des rapports Trivy, et les enrichir avec les données NVD pour une analyse avancée des vulnérabilités.

## Table des matières
- [Installation](#installation)
- [Configuration de la clé API](#configuration-de-la-clé-api)
- [Extraction des cibles](#extraction-des-cibles)
- [Utilisation](#utilisation)
  - [Analyse d'un seul rapport](#analyse-dun-seul-rapport)
  - [Analyse de plusieurs cibles](#analyse-de-plusieurs-cibles)
  - [Génération des rapports](#génération-des-rapports)

## Installation

```bash
# Cloner le dépôt
git clone [URL_DU_REPO]
cd Script_trivy

# Installer les dépendances
pip install -r requirements.txt
```

## Configuration de la clé API

1. Obtenez une clé API gratuite sur [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Créez un fichier `api_config.py` à la racine du projet :
   ```python
   NVD_API_KEY = "votre_clé_api_ici"
   ```
3. **Sécurité** : Ajoutez `api_config.py` à votre `.gitignore`

## Extraction des cibles

### Pour les images Docker

```bash
# Lister toutes les images avec leurs tags
docker images --format "{{.Repository}}:{{.Tag}}" > targets.txt

# Filtrer les images (ex: exclure <none>)
docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>" > targets.txt
```

### Pour les dépôts Git

```bash
# Trouver tous les dépôts Git dans un répertoire
find /chemin/vers/depots -type d -name ".git" | sed 's/\/.git$//' > targets.txt
```

### Pour les applications web (URLs)

```bash
# Liste d'URLs à analyser
echo "https://example1.com" > targets.txt
echo "https://example2.com" >> targets.txt
```

### Format du fichier des cibles (targets.csv)

Le fichier doit être au format CSV avec les colonnes suivantes :

```csv
type,nom,cible,priorite,environnement
image,docker,ubuntu:20.04,high,production
repository,git,https://github.com/user/repo.git,medium,development
web,url,https://example.com,high,staging
fs,chemin,/chemin/vers/dossier,low,test
```

**Colonnes :**
- `type` : Type de cible (`image`, `repository`, `web`, `fs`)
- `nom` : Nom convivial pour identifier la cible
- `cible` : URL, chemin ou identifiant de la cible
- `priorite` : Niveau de priorité (`low`, `medium`, `high`)
- `environnement` : Environnement cible (`production`, `staging`, `development`, `test`)

**Exemple de création avec Excel :**
1. Créez un nouveau classeur Excel
2. Ajoutez les en-têtes de colonnes
3. Remplissez les informations de vos cibles
4. Enregistrez au format CSV (Séparateur: virgule)

## Utilisation

### Analyse d'un seul rapport

1. Générez un rapport Trivy :
   ```bash
   trivy image --format json -o scan.json ubuntu:20.04
   ```

2. Convertissez en CSV si nécessaire :
   ```bash
   python trivy_parser.py -i scan.json -o scan.csv
   ```

3. Enrichissez avec NVD :
   ```bash
   python nvd_client.py -i scan.csv -o scan_enriched.csv
   ```

4. Générez les rapports finaux :
   ```bash
   python repriorise.py -i scan_enriched.csv -o rapports/ -f all
   ```

### Analyse de plusieurs cibles

1. Créez un script `scan_all.py` :
   ```python
   #!/usr/bin/env python3
   import csv
   import subprocess
   import os
   from pathlib import Path
   
   def run_scan(target_type, target, output_file):
       """Exécute Trivy avec les paramètres appropriés"""
       if target_type == 'image':
           cmd = ['trivy', 'image', '--format', 'json', '-o', output_file, target]
       elif target_type == 'repository':
           # Cloner le dépôt si nécessaire
           repo_dir = f"repos/{os.path.basename(target).replace('.git', '')}"
           if not os.path.exists(repo_dir):
               subprocess.run(['git', 'clone', target, repo_dir])
           cmd = ['trivy', 'fs', '--security-checks', 'vuln', '--format', 'json', '-o', output_file, repo_dir]
       elif target_type == 'web':
           cmd = ['trivy', 'webroot', '--url', target, '--format', 'json', '-o', output_file]
       else:  # filesystem
           cmd = ['trivy', 'fs', '--security-checks', 'vuln', '--format', 'json', '-o', output_file, target]
       
       print(f"Exécution: {' '.join(cmd)}")
       result = subprocess.run(cmd, capture_output=True, text=True)
       if result.returncode != 0:
           print(f"Erreur lors de l'analyse de {target}:")
           print(result.stderr)
       return result.returncode == 0
   
   def main():
       # Créer les dossiers nécessaires
       Path("scans").mkdir(exist_ok=True)
       Path("repos").mkdir(exist_ok=True)
       
       # Lire le fichier CSV des cibles
       with open('targets.csv', newline='') as csvfile:
           reader = csv.DictReader(csvfile)
           for row in reader:
               target_type = row['type']
               target_name = row['nom']
               target = row['cible']
               
               print(f"\nAnalyse de {target_name} ({target_type}: {target})")
               
               # Créer un nom de fichier valide
               safe_name = "".join(c if c.isalnum() else "_" for c in target_name)
               output_file = f"scans/{safe_name}.json"
               
               # Exécuter le scan
               if run_scan(target_type, target, output_file):
                   print(f"✓ Scan terminé : {output_file}")
               else:
                   print(f"✗ Échec du scan pour : {target_name}")
   
   if __name__ == "__main__":
       main()
   ```

2. Rendez-le exécutable :
   ```bash
   chmod +x scan_all.py
   ```

3. Exécutez-le :
   ```bash
   python scan_all.py
   ```

2. Rendez-le exécutable :
   ```bash
   chmod +x scan_all.sh
   ```

3. Exécutez-le :
   ```bash
   ./scan_all.sh
   ```

### Génération des rapports

1. Traitez tous les scans :
   ```bash
   # Convertir et fusionner tous les rapports
   python trivy_parser.py -i scans/ -o processed/ --merge all_scans.csv
   
   # Option 1: Enrichir avec NVD et générer les rapports
   python nvd_client.py -i all_scans.csv -o all_enriched.csv
   python repriorise.py -i all_enriched.csv -o rapports/ -f all
   
   # Option 2: Générer des rapports individuels
   for file in scans/*.json; do
       base=$(basename "$file" .json)
       python trivy_parser.py -i "$file" -o "processed/${base}.csv"
       python nvd_client.py -i "processed/${base}.csv" -o "processed/${base}_enriched.csv"
       python repriorise.py -i "processed/${base}_enriched.csv" -o "rapports/${base}/" -f all
   done
   ```

2. Pour analyser n'importe quel rapport existant :
   ```bash
   # Fichier JSON (sortie Trivy)
   python trivy_parser.py -i scan.json -o scan.csv
   
   # Fichier CSV généré par Trivy
   python nvd_client.py -i scan.csv -o scan_enriched.csv
   
   # Fichier déjà enrichi
   python repriorise.py -i scan_enriched.csv -o rapport/
   ```

2. Consultez les rapports dans le dossier `rapports/` :
   - `vulnerabilities_prioritized.csv` : Données complètes au format CSV
   - `vulnerabilities_prioritized.xlsx` : Version Excel avec mise en forme
   - `vulnerabilities_prioritized.pdf` : Rapport PDF avec graphiques

## Bonnes pratiques

- **Mettez à jour régulièrement** la base de données Trivy :
  ```bash
  trivy image --download-db-only
  ```
- **Planifiez des analyses régulières** avec cron ou un outil d'orchestration
- **Vérifiez les limites de l'API NVD** et gérez les quotas
- **Conservez une historique** des analyses pour le suivi dans le temps

### Analyse de plusieurs rapports

```bash
python analyser_multiple.py rapport1.json rapport2.csv rapport3.json
```

Ou placez tous vos rapports dans le dossier et exécutez :
```bash
python analyser_multiple.py
```
Le script détectera automatiquement tous les rapports Trivy.

## Extraction des targets

Pour extraire tous les targets (images, fichiers, etc.) des rapports générés :

```bash
python extract_targets.py
```

Voir [EXTRACT_TARGETS_README.md](EXTRACT_TARGETS_README.md) pour plus de détails.

## Structure

```
Script_trivy/
├── main.py                    # Point d'entrée
├── config.py                  # Configuration
├── trivy_parser.py            # Parser Trivy
├── nvd_client.py              # Client API NVD
├── report_generator.py        # Génération de rapports
├── api_config.py              # ⚠️ CLÉ API (ne pas versionner)
├── analyser_multiple.py       # Analyse de plusieurs rapports
├── extract_targets.py         # 📋 Extraction des targets
├── rapport_vulnerabilites.json # Votre rapport Trivy (JSON)
└── rapport_vulnerabilites.csv  # Ou votre rapport Trivy (CSV)
```

## Format Supporté

- ✅ **CSV** : Format tabulaire de Trivy

Le script détecte automatiquement **n'importe quel fichier .csv** dans le dossier (sauf ceux dans `output/`).
#   c l o u d _ v u l _ m a n a g e m e n t  
 #   c l o u d _ v u l _ m a n a g e m e n t  
 