import os
import json
import logging
from .path_utils import TRANSLATIONS_DIR
from .core import cl

logger = logging.getLogger('mhddos_proxy')
logger.setLevel('INFO')


class Translations:

    def __init__(self, language: str):
        """
        Initialize application-wide localization
        Accept ISO language code, e.g. 'en' or 'ua' in any case
        If localization does not exist, we fall back to EN
        :param language: one of supported languages
        """
        self.translations = {}
        if not os.path.isdir(TRANSLATIONS_DIR):
            logger.warning(f"{cl.RED}Translations directory is not found, fallback to default")
            return
        self.load(language)

    def load(self, language: str):
        """
        Load translations for given language
        :param language: one of supported languages
        """
        if not os.path.isdir(TRANSLATIONS_DIR):
            logger.warning(f"{cl.RED}Translations directory is not found, fallback to default")
            return
        translation_file = f'{TRANSLATIONS_DIR}/{language.lower()}.json'
        if os.path.exists(translation_file):
            logger.info(f"{cl.YELLOW}For language {language} localization file found: {translation_file}")
            with open(translation_file, 'r') as f:
                self.translations = json.load(f)

    def __call__(self, key: str) -> str:
        """
        Get translation for given key,
        Key usually is English string, and if translation is not found,
        we simply return the key itself
        """
        if key in self.translations:
            return self.translations[key]
        else:
            return key


TR = Translations('en')
