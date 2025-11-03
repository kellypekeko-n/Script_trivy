#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module de configuration pour l'analyseur Trivy + NVD
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    """Configuration de l'application"""
    
    # Chemins des fichiers
    trivy_report_path: str = "rapport_vulnerabilites.json"
    output_dir: str = "output"
    
    # API NVD
    nvd_api_key: Optional[str] = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Rate limiting
    rate_limit_delay: float = 0.6  # secondes entre requêtes (100 req/min avec clé API)
    rate_limit_no_key: float = 6.0  # secondes sans clé API (10 req/min)
    request_timeout: int = 10  # timeout des requêtes en secondes
    
    # Rapports
    generate_csv: bool = True
    generate_pdf: bool = True
    generate_visualizations: bool = True
    
    # Logging
    log_file: str = "trivy_analysis.log"
    log_level: str = "INFO"
    
    # Filtres
    min_severity: Optional[str] = None  # None, "LOW", "MEDIUM", "HIGH", "CRITICAL"
    max_cves_to_process: Optional[int] = None  # Limite le nombre de CVE à traiter
    
    @classmethod
    def from_env(cls) -> 'Config':
        """
        Crée une configuration depuis les variables d'environnement
        
        Returns:
            Instance de Config
        """
        return cls(
            trivy_report_path=os.getenv("TRIVY_REPORT", "rapport_vulnerabilites.json"),
            output_dir=os.getenv("OUTPUT_DIR", "output"),
            nvd_api_key=os.getenv("NVD_API_KEY"),
            rate_limit_delay=float(os.getenv("RATE_LIMIT_DELAY", "0.6")),
            log_level=os.getenv("LOG_LEVEL", "INFO")
        )
    
    def validate(self) -> bool:
        """
        Valide la configuration
        
        Returns:
            True si la configuration est valide
        """
        # Vérifier que le fichier Trivy existe
        if not Path(self.trivy_report_path).exists():
            return False
        
        # Créer le répertoire de sortie si nécessaire
        Path(self.output_dir).mkdir(exist_ok=True)
        
        return True
    
    def get_rate_limit(self) -> float:
        """
        Retourne le délai de rate limiting approprié
        
        Returns:
            Délai en secondes
        """
        return self.rate_limit_delay if self.nvd_api_key else self.rate_limit_no_key


# Couleurs pour les niveaux de sévérité
SEVERITY_COLORS = {
    'CRITICAL': '#d32f2f',
    'HIGH': '#f57c00',
    'MEDIUM': '#fbc02d',
    'LOW': '#388e3c',
    'UNKNOWN': '#757575'
}

# Ordre de priorité des sévérités
SEVERITY_ORDER = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'UNKNOWN': 0
}
