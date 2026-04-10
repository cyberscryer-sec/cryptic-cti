print(f"starting spacy import...")
import spacy


_nlp = None
def get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


def sentence_chunks(text: str, target_chars: int = 900, overlap_sentences: int = 1) -> list[str]:
    nlp = get_nlp()
    doc = nlp(text)
    sentences = [sent.text.strip() for sent in doc.sents if sent.text.strip()]
    if not sentences:
        stripped = text.strip()
        return [stripped] if stripped else []
    chunks: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(sentences):
        current = []
        current_len = 0
        start_i = i
        while i < len(sentences):
            sentence = sentences[i]
            projected = current_len + len(sentence) + (1 if current else 0)
            if current and projected > target_chars:
                break
            current.append(sentence)
            current_len = projected
            i += 1
        chunk = " ".join(current).strip()
        if chunk:
            chunks.append(chunk)
        if i >= len(sentences):
            break
        i = max(start_i + 1, i - overlap_sentences)
    return chunks


def char_chunks(text: str, target_chars: int = 900, overlap_chars: int = 150) -> list[str]:
    text = text.strip()
    if not text:
        return []
    chunks = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + target_chars, n)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= n:
            break
        start = max(end - overlap_chars, start + 1)
    return chunks

def chunk_block(block: str) -> list[str]:
    block = block.strip()
    if not block:
        return []
    if len(block) <= 1200 and "\n" not in block:
        return [block]
    if block.count(".") > 2:
        try:
            return sentence_chunks(block, target_chars=700, overlap_sentences=2)
        except Exception as e:
            print(f"Error during sentence chunking: {e}")
            pass
    return char_chunks(block, target_chars=700, overlap_chars=200)

def chunk_block_w_offsets(block: str):
    chunks = []
    offset = 0
    raw_chunks = chunk_block(block) 
    for chunk in raw_chunks:
        start = block.find(chunk, offset)
        end = start + len(chunk)
        chunks.append({
            "text": chunk,
            "start": start,
            "end": end
        })
        offset = end
    return chunks

def dedupe_entities(entities):
    seen = set()
    result = []
    for e in entities:
        key = (e["text"], e["start"], e["end"], e["label"])
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result