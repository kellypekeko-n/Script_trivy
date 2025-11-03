# Script PowerShell pour exécuter un exemple d'analyse
# Usage: .\run_example.ps1

Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Exemple d'Analyse Trivy + NVD                              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Vérifier si Python est installé
Write-Host "[1/5] Vérification de Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ $pythonVersion détecté" -ForegroundColor Green
} catch {
    Write-Host "✗ Python n'est pas installé ou n'est pas dans le PATH" -ForegroundColor Red
    exit 1
}

# Installer les dépendances
Write-Host "`n[2/5] Installation des dépendances..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dépendances installées" -ForegroundColor Green
} else {
    Write-Host "✗ Erreur lors de l'installation des dépendances" -ForegroundColor Red
    exit 1
}

# Configurer les variables d'environnement
Write-Host "`n[3/5] Configuration..." -ForegroundColor Yellow
$env:TRIVY_REPORT = "exemple_rapport_trivy.json"
$env:OUTPUT_DIR = "output"
$env:LOG_LEVEL = "INFO"

# Demander la clé API (optionnel)
Write-Host "`nVoulez-vous utiliser une clé API NVD? (Recommandé)" -ForegroundColor Cyan
Write-Host "Obtenez-en une gratuitement sur: https://nvd.nist.gov/developers/request-an-api-key" -ForegroundColor Gray
$useApiKey = Read-Host "Entrez votre clé API (ou appuyez sur Entrée pour continuer sans)"

if ($useApiKey) {
    $env:NVD_API_KEY = $useApiKey
    Write-Host "✓ Clé API configurée" -ForegroundColor Green
} else {
    Write-Host "⚠ Analyse sans clé API (plus lent)" -ForegroundColor Yellow
}

# Vérifier le fichier d'exemple
Write-Host "`n[4/5] Vérification du rapport Trivy..." -ForegroundColor Yellow
if (Test-Path "exemple_rapport_trivy.json") {
    Write-Host "✓ Fichier exemple trouvé" -ForegroundColor Green
} else {
    Write-Host "✗ Fichier exemple_rapport_trivy.json introuvable" -ForegroundColor Red
    exit 1
}

# Lancer l'analyse
Write-Host "`n[5/5] Lancement de l'analyse..." -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

python main.py

# Résumé
Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Analyse terminée avec succès!" -ForegroundColor Green
    Write-Host "`nConsultez les résultats dans le dossier 'output/':" -ForegroundColor Cyan
    Get-ChildItem -Path "output" -File | ForEach-Object {
        Write-Host "  • $($_.Name)" -ForegroundColor Gray
    }
} else {
    Write-Host "✗ L'analyse a échoué" -ForegroundColor Red
    Write-Host "Consultez le fichier trivy_analysis.log pour plus de détails" -ForegroundColor Yellow
}

Write-Host ""
