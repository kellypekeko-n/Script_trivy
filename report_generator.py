#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module de génération de rapports (CSV, PDF, visualisations)
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER

from config import SEVERITY_COLORS

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Générateur de rapports d'analyse de vulnérabilités"""
    
    def __init__(self, output_dir: str = "output"):
        """
        Initialise le générateur de rapports
        
        Args:
            output_dir: Répertoire de sortie
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def export_to_csv(self, df: pd.DataFrame) -> Path:
        """
        Exporte les données en CSV
        
        Args:
            df: DataFrame à exporter
            
        Returns:
            Chemin du fichier CSV
        """
        csv_path = self.output_dir / f"rapport_vulnerabilites_{self.timestamp}.csv"
        df.to_csv(csv_path, index=False, encoding='utf-8-sig')
        logger.info(f"✓ Rapport CSV sauvegardé: {csv_path}")
        return csv_path
    
    def generate_visualizations(self, df: pd.DataFrame) -> Path:
        """
        Génère des visualisations des vulnérabilités
        
        Args:
            df: DataFrame avec les données enrichies
            
        Returns:
            Chemin du fichier image
        """
        logger.info("Génération des visualisations...")
        
        sns.set_style("whitegrid")
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Répartition par sévérité
        severity_counts = df['severity'].value_counts()
        colors_list = [SEVERITY_COLORS.get(sev, '#757575') for sev in severity_counts.index]
        
        axes[0, 0].pie(severity_counts.values, labels=severity_counts.index, 
                       autopct='%1.1f%%', colors=colors_list, startangle=90)
        axes[0, 0].set_title('Répartition par Sévérité (Trivy)', fontsize=14, fontweight='bold')
        
        # 2. Distribution des scores CVSS
        df_cvss = df[df['cvss_score'] != 'N/A'].copy()
        if not df_cvss.empty:
            df_cvss['cvss_score'] = pd.to_numeric(df_cvss['cvss_score'], errors='coerce')
            df_cvss = df_cvss.dropna(subset=['cvss_score'])
            
            axes[0, 1].hist(df_cvss['cvss_score'], bins=20, edgecolor='black', 
                           color='#1976d2', alpha=0.7)
            axes[0, 1].set_title('Distribution des Scores CVSS', fontsize=14, fontweight='bold')
            axes[0, 1].set_xlabel('Score CVSS')
            axes[0, 1].set_ylabel('Nombre de vulnérabilités')
            if len(df_cvss) > 0:
                axes[0, 1].axvline(df_cvss['cvss_score'].mean(), color='red', 
                                  linestyle='--', label=f'Moyenne: {df_cvss["cvss_score"].mean():.2f}')
                axes[0, 1].legend()
        
        # 3. Top 10 des packages vulnérables
        top_packages = df['pkg_name'].value_counts().head(10)
        if not top_packages.empty:
            axes[1, 0].barh(range(len(top_packages)), top_packages.values, color='#7b1fa2')
            axes[1, 0].set_yticks(range(len(top_packages)))
            axes[1, 0].set_yticklabels(top_packages.index)
            axes[1, 0].set_title('Top 10 des Packages Vulnérables', fontsize=14, fontweight='bold')
            axes[1, 0].set_xlabel('Nombre de vulnérabilités')
            axes[1, 0].invert_yaxis()
        
        # 4. Top 10 des CWE
        cwe_list = []
        for cwe_str in df['cwe_ids']:
            if cwe_str != 'N/A':
                cwe_list.extend([c.strip() for c in str(cwe_str).split(',')])
        
        if cwe_list:
            cwe_series = pd.Series(cwe_list)
            top_cwe = cwe_series.value_counts().head(10)
            axes[1, 1].barh(range(len(top_cwe)), top_cwe.values, color='#c62828')
            axes[1, 1].set_yticks(range(len(top_cwe)))
            axes[1, 1].set_yticklabels(top_cwe.index)
            axes[1, 1].set_title('Top 10 des Types de Faiblesses (CWE)', 
                                fontsize=14, fontweight='bold')
            axes[1, 1].set_xlabel('Occurrences')
            axes[1, 1].invert_yaxis()
        
        plt.tight_layout()
        viz_path = self.output_dir / f"visualisations_{self.timestamp}.png"
        plt.savefig(viz_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"✓ Visualisations sauvegardées: {viz_path}")
        return viz_path
    
    def generate_pdf_report(self, df: pd.DataFrame, stats: Dict, viz_path: Path) -> Path:
        """
        Génère un rapport PDF professionnel
        
        Args:
            df: DataFrame avec les données
            stats: Statistiques globales
            viz_path: Chemin vers les visualisations
            
        Returns:
            Chemin du fichier PDF
        """
        logger.info("Génération du rapport PDF...")
        
        pdf_path = self.output_dir / f"rapport_vulnerabilites_{self.timestamp}.pdf"
        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Styles personnalisés
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1976d2'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#424242'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Titre
        story.append(Paragraph("Rapport d'Analyse de Vulnérabilités", title_style))
        story.append(Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}", 
                              styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Résumé exécutif
        story.append(Paragraph("Résumé Exécutif", heading_style))
        
        summary_data = [
            ["Métrique", "Valeur"],
            ["Total de CVE détectées", str(stats.get('total_cves', 0))],
            ["CVE enrichies avec NVD", str(stats.get('enriched_cves', 0))],
        ]
        
        # Ajout du taux de réussite
        if stats.get('total_cves', 0) > 0:
            success_rate = (stats.get('enriched_cves', 0) / stats['total_cves'] * 100)
            summary_data.append(["Taux de réussite", f"{success_rate:.1f}%"])
        
        # Statistiques de sévérité
        severity_counts = df['severity'].value_counts()
        for severity, count in severity_counts.items():
            summary_data.append([f"Vulnérabilités {severity}", str(count)])
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1976d2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Visualisations
        story.append(Paragraph("Visualisations", heading_style))
        if viz_path.exists():
            img = Image(str(viz_path), width=7*inch, height=5.25*inch)
            story.append(img)
        
        story.append(PageBreak())
        
        # Top 20 des vulnérabilités critiques
        story.append(Paragraph("Top 20 des Vulnérabilités Critiques et Hautes", heading_style))
        
        df_critical = df[df['severity'].isin(['CRITICAL', 'HIGH'])].copy()
        df_critical = df_critical.sort_values('severity', ascending=True).head(20)
        
        if not df_critical.empty:
            vuln_data = [["CVE", "Sévérité", "CVSS", "Package", "CWE"]]
            
            for _, row in df_critical.iterrows():
                cve_id = str(row['cve_id'])[:20]
                severity = str(row['severity'])
                cvss = str(row['cvss_score'])[:6]
                pkg = str(row['pkg_name'])[:25]
                cwe = str(row['cwe_ids'])[:30]
                
                vuln_data.append([cve_id, severity, cvss, pkg, cwe])
            
            vuln_table = Table(vuln_data, colWidths=[1.3*inch, 0.9*inch, 0.6*inch, 1.5*inch, 1.8*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#d32f2f')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            story.append(vuln_table)
        else:
            story.append(Paragraph("Aucune vulnérabilité critique ou haute détectée.", 
                                  styles['Normal']))
        
        # Construction du PDF
        doc.build(story)
        logger.info(f"✓ Rapport PDF sauvegardé: {pdf_path}")
        
        return pdf_path
