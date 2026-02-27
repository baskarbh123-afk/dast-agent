from .base import BaseScanner
from .xss import XSSScanner
from .sqli import SQLiScanner
from .ssrf import SSRFScanner
from .idor import IDORScanner
from .cors import CORSScanner
from .open_redirect import OpenRedirectScanner
from .header_analysis import HeaderAnalysisScanner

SCANNER_REGISTRY = {
    "xss": XSSScanner,
    "sqli": SQLiScanner,
    "ssrf": SSRFScanner,
    "idor": IDORScanner,
    "cors": CORSScanner,
    "open_redirect": OpenRedirectScanner,
    "header_analysis": HeaderAnalysisScanner,
}

__all__ = [
    "BaseScanner",
    "SCANNER_REGISTRY",
    "XSSScanner",
    "SQLiScanner",
    "SSRFScanner",
    "IDORScanner",
    "CORSScanner",
    "OpenRedirectScanner",
    "HeaderAnalysisScanner",
]
