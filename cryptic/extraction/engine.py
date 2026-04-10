from cryptic.extraction.gliner_utils import GlinerRunner
from cryptic.extraction.spacy_utils import SpacyRunner

class ExtractionEngine:
    def __init__(self):
        self.runners = {"spacy": SpacyRunner(), "gliner": GlinerRunner()} # future: RegexRunner(), etc.
    def run(self, text: str) -> dict:
        results = {}
        for name, runner in self.runners:
            name = runner.__class__.__name__.lower()
            results[name] = runner.extract(text)
        return results