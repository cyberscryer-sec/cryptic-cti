from __future__ import annotations

import re
from difflib import SequenceMatcher
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from cryptic.output.cluster_obj import Cluster
from cryptic.output.out_utils import clean_text, top_values

MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"
MAX_INPUT_CHARS = 6000
MAX_NEW_TOKENS = 140
TEMPERATURE = 0.3
TOP_P = 0.9
DO_SAMPLE = False
MAX_RAW_SNIPPETS = 2
MAX_SNIPPET_CHARS = 500


def normalize_line(text: str) -> str:
    text = text.casefold()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\w\s:/@.-]+", "", text)
    return text.strip()


def is_near_duplicate(text: str, seen: list[str]) -> bool:
    threshold = 0.92
    for prior in seen:
        if SequenceMatcher(None, text, prior).ratio() >= threshold:
            return True
    return False


def postprocess_summary(text: str) -> str:
    text = text.strip()
    prefixes = ["summary:", "analyst summary:", "concise summary:", "here is the summary:"]
    lowered = text.lower()
    for prefix in prefixes:
        if lowered.startswith(prefix):
            text = text[len(prefix):].strip()
            break
    text = re.sub(r"\s+", " ", text).strip()
    # Optional: clamp to first 4 sentences if model rambles.
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if len(sentences) > 4:
        text = " ".join(sentences[:4]).strip()
    return text


def split_by_sent(text: str, max_chars: int) -> list[str]:
    text = clean_text(text)
    if not text:
        return []
    units: list[str] = []
    for block in text.split("\n"):
        block = block.strip()
        if not block:
            continue
        parts = re.split(r"(?<=[.!?。！？])\s+", block)
        for part in parts:
            part = part.strip()
            if part:
                units.append(part)
    return units


def compress_text(text: str, max_chars: int, max_lines: int | None = None) -> str:
    cleaned_original = clean_text(text)
    if not text:
        return ""
    raw_units = split_by_sent(text)
    if not raw_units:
        return ""
    deduped_units: list[str] = []
    seen_norm_units: set[str] = set()
    near_dup_seen: list[str] = []
    for unit in raw_units:
        norm = normalize_line(unit)
        if not norm:
            continue
        if norm in seen_norm_units:
            continue
        if is_near_duplicate(norm, near_dup_seen):
            continue
        seen_norm_units.add(norm)
        near_dup_seen.append(norm)
        deduped_units.append(unit)
    if max_lines is not None:
        deduped_units = deduped_units[:max_lines]
    compressed_units: list[str] = []
    used = 0
    for unit in deduped_units:
        extra = len(unit) + (1 if compressed_units else 0)
        compressed_units.append(unit)
        used += extra
        if used >= max_chars:
            break
    output = "\n".join(compressed_units).strip()
    if not output:
        return ""
    if len(output) < len(cleaned_original):
        output += "\n[TRUNCATED]"
    return output


PROMPT_PATH = Path(__file__).with_name("summary_prompt.txt")
SUMMARY_SYSTEM_PROMPT = PROMPT_PATH.read_text(encoding="utf-8").strip()


def load_summary_model(model_name: str = MODEL_NAME):
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
        trust_remote_code=True,
    )
    return tokenizer, model


def build_summary_messages(source_text: str) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
        {"role": "user", "content": f"Source text:\n{source_text}\n\nWrite the summary now."},
    ]


def build_prompt_for_summary(
    cluster: Cluster,
    max_snippets: int = MAX_RAW_SNIPPETS,
    max_snippet_chars: int = MAX_SNIPPET_CHARS,
) -> str:
    lines: list[str] = []
    lines.append(f"Source: {cluster.source or 'unknown'}")
    lines.append(f"Record count: {len(cluster.record_ids)}")
    lines.append(f"Languages: {', '.join(cluster.languages) if cluster.languages else 'unknown'}")
    confidence = cluster.confidence if cluster.confidence is not None else "unknown"
    lines.append(f"Confidence: {confidence}")
    if cluster.malware_or_tools:
        lines.append(f"Malware/tools: {', '.join(top_values(cluster.malware_or_tools, 5))}")
    if cluster.activities:
        lines.append(f"Activities: {', '.join(top_values(cluster.activities, 5))}")
    if cluster.credential_data_types:
        creds = ", ".join(top_values(cluster.credential_data_types, 5))
        lines.append(f"Credential/data types: {creds}")
    if cluster.platforms:
        lines.append(f"Platforms/apps: {', '.join(top_values(cluster.platforms, 5))}")
    if cluster.indicators:
        indicators = [f"{item.type}:{item.value}" for item in cluster.indicators]
        lines.append(f"Indicators: {', '.join(indicators)}")
    else:
        lines.append("Indicators: none")
    if cluster.representative_text:
        lines.append("")
        lines.append("Representative text:")
        clean_rep_text = clean_text(cluster.representative_text)
        lines.append(clean_rep_text)
    raw_snippets = []
    for text in cluster.raw_texts:
        cleaned = clean_text(text)
        if not cleaned:
            continue
        if cluster.representative_text and cleaned == clean_rep_text:
            continue
        raw_snippets.append(compress_text(cleaned, max_chars=max_snippet_chars))
        if len(raw_snippets) >= max_snippets:
            break
    if raw_snippets:
        lines.append("")
        lines.append("Additional raw text snippets:")
        for idx, snippet in enumerate(raw_snippets, start=1):
            lines.append(f"{idx}. {snippet}")
    return "\n".join(lines).strip()


def summary_from_text(
    source_text: str,
    tokenizer,
    model,
    max_input_chars: int = MAX_INPUT_CHARS,
    max_new_tokens: int = MAX_NEW_TOKENS,
    temperature: float = TEMPERATURE,
    top_p: float = TOP_P,
    do_sample: bool = DO_SAMPLE,
) -> str:
    cleaned = clean_text(source_text)
    truncated = compress_text(cleaned, max_chars=max_input_chars)
    messages = build_summary_messages(truncated)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    model_inputs = tokenizer([prompt], return_tensors="pt").to(model.device)
    with torch.no_grad():
        output_ids = model.generate(
            **model_inputs,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            top_p=top_p,
            do_sample=do_sample,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated_ids = output_ids[0][len(model_inputs.input_ids[0]):]
    raw_output = tokenizer.decode(generated_ids, skip_special_tokens=True)
    return postprocess_summary(raw_output)


def summary_from_cluster(
    cluster: Cluster,
    tokenizer,
    model,
    max_input_chars: int = MAX_INPUT_CHARS,
    max_new_tokens: int = MAX_NEW_TOKENS,
    temperature: float = TEMPERATURE,
    top_p: float = TOP_P,
    do_sample: bool = DO_SAMPLE,
) -> str:
    source_text = build_prompt_for_summary(cluster)
    return summary_from_text(
        source_text=source_text,
        tokenizer=tokenizer,
        model=model,
        max_input_chars=max_input_chars,
        max_new_tokens=max_new_tokens,
        temperature=temperature,
        top_p=top_p,
        do_sample=do_sample,
    )


def llm_summary_text(tokenizer, model):
    def builder(cluster: Cluster) -> str:
        return summary_from_cluster(cluster, tokenizer=tokenizer, model=model)

    return builder


def det_summary_text(cluster: Cluster) -> str:
    malware = top_values(cluster.malware_or_tools, 3)
    activities = top_values(cluster.activities, 3)
    creds = top_values(cluster.credential_data_types, 4)
    platforms = top_values(cluster.platforms, 3)
    parts: list[str] = []
    evidence_parts: list[str] = []
    if malware:
        evidence_parts.append(f"malware/tool references: {', '.join(malware)}")
    if activities:
        evidence_parts.append(f"activity mentions: {', '.join(activities)}")
    if creds:
        evidence_parts.append(f"credential/data mentions: {', '.join(creds)}")
    if platforms:
        evidence_parts.append(f"platform/app mentions: {', '.join(platforms)}")
    if evidence_parts:
        parts.append("This cluster contains " + "; ".join(evidence_parts) + ".")
    else:
        parts.append(
            "This cluster contains limited structured signal after normalization and clustering."
        )
    if len(cluster.languages) > 1:
        parts.append(f"This cluster contains multilingual reporting: {cluster.languages}")
    if len(cluster.record_ids) > 1:
        parts.append(
            f"The cluster aggregates {len(cluster.record_ids)} related records "
            f"from source {cluster.source}."
        )
    else:
        parts.append(f"The cluster is based on a single record from source {cluster.source}.")
    return " ".join(parts)
