from collections_workflow.cryptic.extraction.spacy_utils import detect_lang, has_chinese, has_latin


def test_detect_language_en():
    assert detect_lang("Vega Stealer steals login credentials.") == "en"


def test_detect_language_zh():
    assert detect_lang("窃取登录凭证和信用卡信息") == "zh"


def test_detect_language_mixed():
    assert detect_lang("Vega Stealer 窃取登录凭证") == "mixed"


def test_has_chinese():
    assert has_chinese("测试")
    assert not has_chinese("test only")


def test_has_latin():
    assert has_latin("test")
    assert not has_latin("测试")