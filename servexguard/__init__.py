"""
🛡️ ServeX Guard — Production quality gate for RAG & LLM systems.

Evaluate quality. Detect PII leaks. Block prompt injections. Stop drift.
By ServeX AI — El Mahdi El Aimani
"""

__version__ = "0.1.0"
__author__ = "El Mahdi El Aimani"
__email__ = "mahdielaimani@gmail.com"

from servexguard.core import CheckStatus, GuardResult, ServeXGuard

__all__ = ["ServeXGuard", "GuardResult", "CheckStatus"]
