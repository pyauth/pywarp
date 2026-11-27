import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

project = "PyWARP"
copyright = "2019, Andrey Kislyuk"
author = "Andrey Kislyuk"
language = "en"

extensions = ["sphinx.ext.autodoc", "sphinx.ext.viewcode"]
exclude_patterns = ["_build", "html", "Thumbs.db", ".DS_Store"]
autodoc_typehints = "description"

html_theme = "furo"
