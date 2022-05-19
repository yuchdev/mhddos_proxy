# -*- coding: utf-8 -*-
import os
import pathlib

PROJECT_DIR = os.path.abspath((os.path.join(os.path.dirname(__file__), "..")))
HOME_DIR = os.path.join(pathlib.Path.home())
CONFIG_DEFAULT_PATH = os.path.join(HOME_DIR, '.uareaper.json')
TRANSLATIONS_DIR = os.path.join(PROJECT_DIR, 'translations')
