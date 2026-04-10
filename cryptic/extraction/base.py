from abc import ABC, abstractmethod

class ExtractionRunner(ABC):
    @abstractmethod
    def extract(self, text: str) -> list[dict]:
        pass