#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script principal d'analyse de vulnérabilités Trivy enrichi avec NVD
Auteur: Kelly Pekeko
Version: 1.0
"""

import sys
import logging
import time
import pandas as pd
from pathlib import Path

from config import Config
from trivy_parser import TrivyParser
from nvd_client import NVDClient
from report_generator import ReportGenerator


def setup_logging(log_file: str, log_level: str):
    """
    Configure le système de logging
    
    Args:
        log_file: Chemin du fichier de log
        log_level: Niveau de log (DEBUG, INFO, WARNING, ERROR)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )


def print_banner():
    """Affiche la bannière du programme"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Analyseur de Vulnérabilités Trivy + NVD                    ║
║   Version 1.0 - Kelly Pekeko                                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def enrich_cves_with_nvd(cve_list: list, nvd_client: NVDClient, rate_limit: float) -> pd.DataFrame:
    """
    Enrichit les CVE avec les données NVD
    
    Args:
        cve_list: Liste des CVE extraites de Trivy
        nvd_client: Client NVD
        rate_limit: Délai entre les requêtes
        
    Returns:
        DataFrame pandas avec les données enrichies
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Enrichissement de {len(cve_list)} CVE avec l'API NVD...")
    
    enriched_data = []
    
    for idx, cve_info in enumerate(cve_list, 1):
        cve_id = cve_info["cve_id"]
        logger.info(f"[{idx}/{len(cve_list)}] Traitement de {cve_id}...")
        
        # Requête NVD
        nvd_info = nvd_client.query_cve(cve_id)
        
        # Fusion des données Trivy et NVD
        merged_data = {**cve_info}
        
        if nvd_info:
            merged_data.update(nvd_info)
        else:
            # Valeurs par défaut si NVD échoue
            merged_data.update({
                "cvss_score": "N/A",
                "cvss_severity": "N/A",
                "cvss_vector": "N/A",
                "cvss_version": "N/A",
                "description_nvd": "N/A",
                "cwe_ids": "N/A",
                "published_date": "N/A",
                "last_modified_date": "N/A",
                "reference_urls": "N/A"
            })
        
        enriched_data.append(merged_data)
        
        # Respect du rate limit
        if idx < len(cve_list):
            time.sleep(rate_limit)
    
    df = pd.DataFrame(enriched_data)
    logger.info(f"✓ Enrichissement terminé")
    
    return df


def main():
    """
    Fonction principale
    """
    print_banner()
    
    # Chargement de la configuration
    config = Config.from_env()
    
    # Configuration du logging
    setup_logging(config.log_file, config.log_level)
    logger = logging.getLogger(__name__)
    
    logger.info("="*60)
    logger.info("DÉMARRAGE DE L'ANALYSE TRIVY + NVD")
    logger.info("="*60)
    
    # Validation de la configuration
    if not config.validate():
        logger.error(f"✗ Fichier Trivy introuvable: {config.trivy_report_path}")
        logger.info("💡 Générez un rapport Trivy avec:")
        logger.info("   trivy image -f json -o rapport_vulnerabilites.json <image>")
        return 1
    
    # Vérification de la clé API
    if not config.nvd_api_key:
        logger.warning("⚠ Aucune clé API NVD fournie. Les requêtes seront limitées.")
        logger.info("💡 Conseil: Définissez la variable d'environnement NVD_API_KEY")
        logger.info("   Obtenez une clé gratuite sur: https://nvd.nist.gov/developers/request-an-api-key")
    
    try:
        # ÉTAPE 1: Parser le rapport Trivy
        logger.info("\n[ÉTAPE 1/5] Parsing du rapport Trivy")
        parser = TrivyParser(config.trivy_report_path)
        
        if not parser.load_report():
            return 1
        
        cve_list = parser.extract_cves(min_severity=config.min_severity)
        
        if not cve_list:
            logger.error("✗ Aucune CVE trouvée dans le rapport")
            return 1
        
        # Limiter le nombre de CVE si configuré
        if config.max_cves_to_process:
            cve_list = cve_list[:config.max_cves_to_process]
            logger.info(f"⚠ Limitation à {config.max_cves_to_process} CVE")
        
        # Statistiques Trivy
        trivy_stats = parser.get_statistics()
        logger.info(f"📊 Statistiques Trivy: {trivy_stats['total_cves']} CVE détectées")
        
        # ÉTAPE 2: Enrichir avec NVD
        logger.info("\n[ÉTAPE 2/5] Enrichissement avec l'API NVD")
        nvd_client = NVDClient(api_key=config.nvd_api_key, base_url=config.nvd_base_url)
        
        df = enrich_cves_with_nvd(
            cve_list, 
            nvd_client, 
            config.get_rate_limit()
        )
        
        # Statistiques NVD
        nvd_stats = nvd_client.get_statistics()
        logger.info(f"📊 Statistiques NVD: {nvd_stats}")
        
        # ÉTAPE 3: Génération des rapports
        logger.info("\n[ÉTAPE 3/5] Génération des rapports")
        report_gen = ReportGenerator(config.output_dir)
        
        # CSV
        if config.generate_csv:
            csv_path = report_gen.export_to_csv(df)
        
        # Visualisations
        viz_path = None
        if config.generate_visualizations:
            logger.info("\n[ÉTAPE 4/5] Génération des visualisations")
            viz_path = report_gen.generate_visualizations(df)
        
        # PDF
        if config.generate_pdf and viz_path:
            logger.info("\n[ÉTAPE 5/5] Génération du rapport PDF")
            stats = {
                'total_cves': trivy_stats['total_cves'],
                'enriched_cves': nvd_stats['successful']
            }
            pdf_path = report_gen.generate_pdf_report(df, stats, viz_path)
        
        # Résumé final
        logger.info("\n" + "="*60)
        logger.info("✓ ANALYSE TERMINÉE AVEC SUCCÈS")
        logger.info("="*60)
        logger.info(f"📊 Total CVE: {trivy_stats['total_cves']}")
        logger.info(f"✓ Enrichies: {nvd_stats['successful']}")
        logger.info(f"✗ Échecs: {nvd_stats['failed']}")
        logger.info(f"📈 Taux de réussite: {nvd_stats['success_rate']}")
        
        if config.generate_csv:
            logger.info(f"📄 Rapport CSV: {csv_path}")
        if config.generate_pdf:
            logger.info(f"📄 Rapport PDF: {pdf_path}")
        if config.generate_visualizations:
            logger.info(f"📊 Visualisations: {viz_path}")
        
        logger.info("="*60)
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("\n⚠ Analyse interrompue par l'utilisateur")
        return 130
    except Exception as e:
        logger.error(f"\n✗ Erreur fatale: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())