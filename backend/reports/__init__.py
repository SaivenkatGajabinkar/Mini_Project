"""
CyberShield Reports Module
Provides PDF and HTML report generation for network capture analyses.
"""

from .pdf_generator import generate_pdf_report

__all__ = ["generate_pdf_report"]
