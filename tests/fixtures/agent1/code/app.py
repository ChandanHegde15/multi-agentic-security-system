# Hand-written fixture for Agent 1 tests. It must never be executed:
# executing it would create a marker file that the tests look for.
import os
import sys, json
from pathlib import Path
import numpy as np
import cv2
from sklearn.model_selection import train_test_split
import requests
import requests.adapters
from . import sibling
from .helpers import thing
import localpkg.module
import totally_made_up_pkg_xyz

try:
    import ujson as fastjson
except ImportError:
    fastjson = None

if sys.platform == "win32":
    import winreg

mod = __import__("yaml")
import importlib
plugin = importlib.import_module("dateutil.parser")
dyn = importlib.import_module(os.environ.get("PLUGIN", "x"))

text = "import not_a_real_import"
# import also_not_real

Path("AGENT1_EXECUTED_MARKER").write_text("executed")
raise SystemExit("this file must never run")
