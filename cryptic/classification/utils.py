from __future__ import annotations
from pathlib import Path
from setfit import SetFitModel

def load_model(model_dir: Path) -> SetFitModel:
    if not model_dir.exists():
        raise FileNotFoundError(f"SetFit model directory not found in: {model_dir}")
    return SetFitModel.from_pretrained(str(model_dir), tokenizer_kwargs={"fix_mistral_regex": True})