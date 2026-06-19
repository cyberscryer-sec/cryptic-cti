from cryptic.extraction.regex_utils import RegexRunner, merge_indicator_lists


class ExtractionEngine:
    def __init__(self):
        from cryptic.extraction.gliner_utils import GlinerRunner
        from cryptic.extraction.spacy_utils import SpacyRunner

        self.runners = {"spacy": SpacyRunner(), "gliner": GlinerRunner(), "regex": RegexRunner()}
    def run(self, record: dict) -> dict:
        results = dict(record)
        text = (
            record.get("text")
            or record.get("raw_text")
            or record.get("content")
            or ""
        )
        for name, runner in self.runners.items():
            extracted = runner.extract(text)
            if isinstance(extracted, dict):
                if "indicators" in extracted:
                    extracted = dict(extracted)
                    extracted["indicators"] = merge_indicator_lists(
                        results.get("indicators", []),
                        extracted.get("indicators", []),
                    )
                results.update(extracted)
            else:
                results[name] = extracted
        return results
