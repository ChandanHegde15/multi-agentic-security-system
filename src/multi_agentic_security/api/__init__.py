"""FastAPI web layer for the Multi-Agentic Security System.

The server is started with ``uvicorn multi_agentic_security.api.app:app``; the ``app`` object is created
only then (see app.py), so importing this package has no side effects.
"""

from .app import create_app
from .service import ScanService

__all__ = ["ScanService", "create_app"]
