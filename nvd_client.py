#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module client pour l'API NVD (National Vulnerability Database)
"""

import requests
import time
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class NVDClient:
    """Client pour interroger l'API NVD"""
    
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"):
        """
        Initialise le client NVD
        
        Args:
            api_key: Clé API NVD (optionnelle mais recommandée)
            base_url: URL de base de l'API NVD
        """
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"apiKey": api_key} if api_key else {}
        self.request_count = 0
        self.success_count = 0
        self.failure_count = 0
    
    def query_cve(self, cve_id: str, timeout: int = 10) -> Optional[Dict]:
        """
        Interroge l'API NVD pour un CVE spécifique
        
        Args:
            cve_id: Identifiant CVE (ex: CVE-2023-1234)
            timeout: Timeout de la requête en secondes
            
        Returns:
            Dictionnaire avec les données NVD ou None
        """
        self.request_count += 1
        
        try:
            url = f"{self.base_url}?cveId={cve_id}"
            response = requests.get(url, headers=self.headers, timeout=timeout)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    enriched_data = self._parse_cve_data(cve_id, cve_data)
                    self.success_count += 1
                    return enriched_data
                else:
                    logger.warning(f"⚠ Aucune donnée pour {cve_id}")
                    self.failure_count += 1
                    return None
            
            elif response.status_code == 404:
                logger.warning(f"⚠ CVE non trouvé dans NVD: {cve_id}")
                self.failure_count += 1
            elif response.status_code == 403:
                logger.error("✗ Accès refusé - Vérifiez votre clé API")
                self.failure_count += 1
            else:
                logger.warning(f"⚠ Erreur API {response.status_code} pour {cve_id}")
                self.failure_count += 1
            
            return None
            
        except requests.exceptions.Timeout:
            logger.warning(f"⚠ Timeout pour {cve_id}")
            self.failure_count += 1
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Erreur réseau pour {cve_id}: {e}")
            self.failure_count += 1
            return None
        except Exception as e:
            logger.error(f"✗ Erreur inattendue pour {cve_id}: {e}")
            self.failure_count += 1
            return None
    
    def _parse_cve_data(self, cve_id: str, cve_data: Dict) -> Dict:
        """
        Parse les données CVE du NVD
        
        Args:
            cve_id: Identifiant CVE
            cve_data: Données brutes du NVD
            
        Returns:
            Dictionnaire structuré
        """
        # Extraction du score CVSS
        metrics = cve_data.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else \
                  metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics else {}
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if "cvssMetricV2" in metrics else {}
        
        cvss_score = "N/A"
        cvss_severity = "N/A"
        cvss_vector = "N/A"
        cvss_version = "N/A"
        
        if cvss_v3:
            cvss_data = cvss_v3.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            cvss_severity = cvss_data.get("baseSeverity", "N/A")
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "3.x"
        elif cvss_v2:
            cvss_data = cvss_v2.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", "N/A")
            cvss_severity = cvss_v2.get("baseSeverity", "N/A")
            cvss_vector = cvss_data.get("vectorString", "N/A")
            cvss_version = "2.0"
        
        # Extraction des descriptions
        descriptions = cve_data.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")
        
        # Extraction des CWE (Common Weakness Enumeration)
        weaknesses = cve_data.get("weaknesses", [])
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_value = desc.get("value", "")
                    if cwe_value:
                        cwe_list.append(cwe_value)
        cwe_ids = ", ".join(cwe_list) if cwe_list else "N/A"
        
        # Dates de publication
        published = cve_data.get("published", "N/A")
        last_modified = cve_data.get("lastModified", "N/A")
        
        # Références
        references = cve_data.get("references", [])
        reference_urls = [ref.get("url", "") for ref in references[:5]]  # Limiter à 5
        
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector": cvss_vector,
            "cvss_version": cvss_version,
            "description_nvd": description,
            "cwe_ids": cwe_ids,
            "published_date": published,
            "last_modified_date": last_modified,
            "reference_urls": ", ".join(reference_urls)
        }
    
    def get_statistics(self) -> Dict:
        """
        Retourne les statistiques du client
        
        Returns:
            Dictionnaire de statistiques
        """
        success_rate = (self.success_count / self.request_count * 100) if self.request_count > 0 else 0
        
        return {
            "total_requests": self.request_count,
            "successful": self.success_count,
            "failed": self.failure_count,
            "success_rate": f"{success_rate:.1f}%"
        }
