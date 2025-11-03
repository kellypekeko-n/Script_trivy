#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module de parsing des rapports Trivy
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class TrivyParser:
    """Parser pour les rapports JSON de Trivy"""
    
    def __init__(self, report_path: str):
        """
        Initialise le parser
        
        Args:
            report_path: Chemin vers le rapport JSON Trivy
        """
        self.report_path = Path(report_path)
        self.data = None
        self.cve_list = []
    
    def load_report(self) -> bool:
        """
        Charge le rapport Trivy depuis le fichier JSON
        
        Returns:
            True si le chargement réussit, False sinon
        """
        try:
            logger.info(f"Chargement du rapport Trivy: {self.report_path}")
            with open(self.report_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            logger.info("✓ Rapport Trivy chargé avec succès")
            return True
        except FileNotFoundError:
            logger.error(f"✗ Fichier introuvable: {self.report_path}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"✗ Erreur de parsing JSON: {e}")
            return False
        except Exception as e:
            logger.error(f"✗ Erreur inattendue: {e}")
            return False
    
    def extract_cves(self, min_severity: Optional[str] = None) -> List[Dict]:
        """
        Extrait les CVE du rapport Trivy avec leurs métadonnées
        
        Args:
            min_severity: Sévérité minimale à extraire (None pour tout)
        
        Returns:
            Liste des CVE avec informations de base
        """
        if not self.data:
            logger.error("✗ Aucune donnée chargée. Appelez load_report() d'abord.")
            return []
        
        cve_dict = {}
        severity_filter = self._get_severity_filter(min_severity)
        
        try:
            results = self.data.get("Results", [])
            logger.info(f"Extraction des CVE depuis {len(results)} résultat(s)...")
            
            for result in results:
                target = result.get("Target", "Unknown")
                vulnerabilities = result.get("Vulnerabilities", [])
                
                for vuln in vulnerabilities:
                    cve_id = vuln.get("VulnerabilityID")
                    severity = vuln.get("Severity", "UNKNOWN")
                    
                    # Filtrer par sévérité si nécessaire
                    if severity_filter and severity not in severity_filter:
                        continue
                    
                    if cve_id and cve_id.startswith("CVE-"):
                        if cve_id not in cve_dict:
                            cve_dict[cve_id] = {
                                "cve_id": cve_id,
                                "severity": severity,
                                "pkg_name": vuln.get("PkgName", "N/A"),
                                "installed_version": vuln.get("InstalledVersion", "N/A"),
                                "fixed_version": vuln.get("FixedVersion", "N/A"),
                                "target": target,
                                "title": vuln.get("Title", "N/A"),
                                "description": vuln.get("Description", "N/A"),
                                "references": vuln.get("References", [])
                            }
            
            self.cve_list = list(cve_dict.values())
            logger.info(f"✓ {len(self.cve_list)} CVE uniques détectées")
            
            return self.cve_list
            
        except Exception as e:
            logger.error(f"✗ Erreur lors de l'extraction des CVE: {e}")
            return []
    
    def _get_severity_filter(self, min_severity: Optional[str]) -> Optional[set]:
        """
        Crée un filtre de sévérité
        
        Args:
            min_severity: Sévérité minimale
            
        Returns:
            Set des sévérités acceptées ou None
        """
        if not min_severity:
            return None
        
        severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if min_severity not in severity_levels:
            return None
        
        min_index = severity_levels.index(min_severity)
        return set(severity_levels[min_index:])
    
    def get_statistics(self) -> Dict:
        """
        Calcule des statistiques sur les CVE extraites
        
        Returns:
            Dictionnaire de statistiques
        """
        if not self.cve_list:
            return {}
        
        stats = {
            "total_cves": len(self.cve_list),
            "by_severity": {},
            "by_package": {},
            "fixable": 0,
            "unfixable": 0
        }
        
        for cve in self.cve_list:
            # Par sévérité
            severity = cve["severity"]
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Par package
            pkg = cve["pkg_name"]
            stats["by_package"][pkg] = stats["by_package"].get(pkg, 0) + 1
            
            # Fixable ou non
            if cve["fixed_version"] != "N/A" and cve["fixed_version"]:
                stats["fixable"] += 1
            else:
                stats["unfixable"] += 1
        
        return stats
