"""Documented Python import-name -> PyPI distribution table (``import_map/1``, D-050).

An import name says which module is loaded, not which distribution provides
it. Only the entries below are mapped; every other third-party import stays
``unresolved`` (D-047). The table lists only widely documented cases where the
import name differs from the distribution name and one maintained distribution
is the usual provider. Ambiguous import names (several distributions install
the same module, e.g. ``Crypto``, ``google``, ``faiss``) are deliberately left
out.

Provenance: curated by the project from the distributions' own installation
instructions. It was NOT derived from any evaluation dataset; its overlap with
the Package Hallucination import pairs is reported in D-050. Each entry is
unverified until Agent 2 confirms the distribution exists in the registry.
"""

from __future__ import annotations

IMPORT_MAP_VERSION = "import_map/1"

# import top-level module -> distribution name (raw, as published)
IMPORT_TO_DISTRIBUTION: dict[str, str] = {
    "attr": "attrs",
    "Bio": "biopython",
    "bs4": "beautifulsoup4",
    "cairo": "pycairo",
    "cv2": "opencv-python",
    "dateutil": "python-dateutil",
    "docx": "python-docx",
    "dotenv": "python-dotenv",
    "fitz": "PyMuPDF",
    "gi": "PyGObject",
    "git": "GitPython",
    "github": "PyGithub",
    "jose": "python-jose",
    "jwt": "PyJWT",
    "kafka": "kafka-python",
    "ldap": "python-ldap",
    "magic": "python-magic",
    "memcache": "python-memcached",
    "multipart": "python-multipart",
    "MySQLdb": "mysqlclient",
    "nacl": "PyNaCl",
    "OpenGL": "PyOpenGL",
    "OpenSSL": "pyOpenSSL",
    "PIL": "pillow",
    "pkg_resources": "setuptools",
    "pptx": "python-pptx",
    "pythoncom": "pywin32",
    "serial": "pyserial",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    "slugify": "python-slugify",
    "socks": "PySocks",
    "telegram": "python-telegram-bot",
    "usb": "pyusb",
    "win32api": "pywin32",
    "win32com": "pywin32",
    "wx": "wxPython",
    "Xlib": "python-xlib",
    "yaml": "PyYAML",
    "zmq": "pyzmq",
}
