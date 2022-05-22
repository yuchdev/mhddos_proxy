import json


LANGUAGES = ['ua', 'en']


class _Translations:
    def __init__(self):
        self.language = None
        with open('src/translations.json', 'r') as f:
            self.translations = json.load(f)

    def set_language(self, language: str):
        assert language in LANGUAGES
        self.language = language

    def translate(self, key: str) -> str:
        try:
            return self.translations[key][self.language]
        except KeyError:
            return key


_inst = _Translations()

set_language = _inst.set_language
translate = _inst.translate
