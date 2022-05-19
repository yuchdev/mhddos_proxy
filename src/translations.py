import os
import json
from .path_utils import TRANSLATIONS_DIR


class Translations:

    def __init__(self, language: str):
        """
        Initialize application-wide localization
        Accept ISO language code, e.g. 'en' or 'ua' in any case
        If localization does not exist, we fall back to EN
        :param language: one of supported languages
        """
        self.translations = {}
        self.load(language)

    def load(self, language: str):
        """
        Load translations for given language
        :param language: one of supported languages
        """
        translation_file = f'{TRANSLATIONS_DIR}/{language.lower()}.json'
        if os.path.exists(translation_file):
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
