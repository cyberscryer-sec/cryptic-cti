model_name = "urchade/gliner_medium-v2.1"

_model = None


def get_gliner_model():
    global _model
    if _model is None:
        from gliner import GLiNER

        _model = GLiNER.from_pretrained(model_name)
    return _model
