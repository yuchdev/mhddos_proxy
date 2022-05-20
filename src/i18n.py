import json


LANGUAGES = ['EN', 'UA']


class _Translations:
    def __init__(self):
        self.language = LANGUAGES[0]
        with open('src/translations.json', 'r') as f:
            self.translations = json.load(f)

    def set_language(self, language: str):
        assert language in LANGUAGES
        self.language = language.lower()

    def translate(self, key: str) -> str:
        try:
            return self.translations[key][self.language]
        except KeyError:
            return key


_inst = _Translations()

set_language = _inst.set_language
translate = _inst.translate
