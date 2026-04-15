from __future__ import annotations
import re
import torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer
from cryptic.output.output_obj import Output
from cryptic.output.summary_obj import Summary
from cryptic.output.cluster_obj import Cluster


def top_values(values: list[str], limit: int = 3) -> list[str]:
    return [v for v in values if isinstance(v, str) and v.strip()][:limit]


def build_summary_text(cluster: Cluster) -> str:
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
        parts.append("This cluster contains limited structured signal after normalization and clustering.")
    if len(cluster.lang) > 1:
        parts.append(f"This cluster merges multilingual reporting across {', '.join(cluster.languages)} records.")
    if len(cluster.record_ids) > 1:
        parts.append(
            f"The cluster aggregates {len(cluster.record_ids)} related records from source {cluster.source}.")
    else:
        parts.append(f"The cluster is based on a single record from source {cluster.source}.")
    return " ".join(parts)


def build_gaps(cluster: Cluster) -> list[str]:
    gaps: list[str] = []
    if not cluster.malware_or_tools:
        gaps.append("No strong malware/tool name extracted.")
    if not cluster.activities:
        gaps.append("No explicit normalized activity extracted.")
    if not cluster.credential_data_types:
        gaps.append("No credential/data type extracted.")
    if not cluster.platforms:
        gaps.append("No platform/app context extracted.")
    if not cluster.indicators:
        gaps.append("No indicators retained in the cluster.")
    return gaps


# def compute_confidence():



def cluster_to_summary(cluster: Cluster) -> Summary:
    summary_text = build_summary_text(cluster)
    gaps = build_gaps(cluster)
    # confidence = compute_confidence(cluster)
    return Summary(
        cluster_id=cluster.id,
        source=cluster.source,
        record_ids=cluster.record_ids,
        lang=cluster.languages,
        summary_text=summary_text,
        representative_text=cluster.representative_text,
        malware_or_tools=cluster.malware_or_tools,
        activities=cluster.activities,
        credential_data_types=cluster.credential_data_types,
        platforms=cluster.platforms,
        indicator_count=len(cluster.indicators),
        # confidence=confidence,
        gaps=gaps,
    )

def summary_to_output(summary: Summary) -> Output:
    payload = summary.to_dict()
    tags: list[str] = []
    if summary.source:
        tags.append(summary.source)
    tags.extend(summary.languages[:2])
    tags.extend(summary.malware_or_tools[:2])
    tags.extend(summary.activities[:2])
    deduped_tags: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        cleaned = tag.strip()
        if not cleaned:
            continue
        norm = cleaned.casefold()
        if norm in seen:
            continue
        seen.add(norm)
        deduped_tags.append(cleaned)
    return Output(
        type="cluster_summary",
        producer=summary.source,
        source_ids=summary.record_ids,
        confidence=summary.confidence,
        tags=deduped_tags,
        payload=payload,
    )

MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"
MAX_INPUT_CHARS = 6000
MAX_NEW_TOKENS = 140
TEMPERATURE = 0.3
TOP_P = 0.9
DO_SAMPLE = False

def clean_source_text(text: str) -> str:
    text = text.replace("\u0000", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def truncate_for_prompt(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + "\n\n[TRUNCATED]"


def postprocess_summary(text: str) -> str: # strip model junk
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
        {"role": "user", "content": f"Source text:\n{source_text}\n\nWrite the summary now."}]


def generate_summary_text(
    source_text: str,
    tokenizer,
    model,
    max_input_chars: int = MAX_INPUT_CHARS,
    max_new_tokens: int = MAX_NEW_TOKENS,
    temperature: float = TEMPERATURE,
    top_p: float = TOP_P,
    do_sample: bool = DO_SAMPLE,
) -> str:
    cleaned = clean_source_text(source_text)
    truncated = truncate_for_prompt(cleaned, max_input_chars=max_input_chars)
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