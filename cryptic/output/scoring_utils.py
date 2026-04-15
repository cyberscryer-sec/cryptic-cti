from __future__ import annotations
from typing import Iterable, Any
from cryptic.output.out_utils import drop_junk
from cryptic.output.cluster_obj import Cluster


def clamp_score(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def to_percent(value: float) -> int:
    return round(clamp_score(value) * 100)


def capped_ratio(count: int, cap: int) -> float:
    if cap <= 0:
        raise ValueError("cap must be > 0")
    return clamp_score(min(count, cap) / cap)


def coverage_ratio(groups: Iterable[list[object] | tuple[object, ...] | set[object]]) -> float:
    groups = list(groups)
    if not groups:
        return 0.0
    populated = sum(1 for group in groups if group)
    return populated / len(groups)


def survival_ratio(kept: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return clamp_score(kept / total)


def weighted_sum(components: dict[str, tuple[float, float]]) -> float:
    # e.g. components = {"coverage": (value_0_to_1, weight), "support": (value_0_to_1, weight)}
    total_weight = sum(weight for _, weight in components.values())
    if total_weight <= 0:
        raise ValueError("total weight must be > 0")
    score = sum(value * weight for value, weight in components.values()) / total_weight
    return clamp_score(score)


def normed_val_confidence(best_score: float | None, support_count: int, cap: int = 3) -> int | None:
    if best_score is None and support_count <= 0:
        return None
    best = clamp_score(best_score if best_score is not None else 0.0)
    corroboration = capped_ratio(support_count, cap)
    # confidence is 70/30 composite of the highest extraction score and how often this candidate was extracted
    score = weighted_sum({"best_score": (best, 0.7), "corroboration": (corroboration, 0.3)})
    return to_percent(score)


def compute_cluster_confidence(cluster: Cluster, members: list[dict[str, Any]]) -> int | None:
    coverage = coverage_ratio([cluster.malware_or_tools, cluster.activities, cluster.credential_data_types, cluster.platforms])
    record_support = capped_ratio(len(cluster.record_ids), 4)
    indicator_support = capped_ratio(len(cluster.indicators), 6)
    support = weighted_sum({
        "records": (record_support, 0.6), # 60/40 split on num records vs num indicators
        "indicators": (indicator_support, 0.4),
    })
    raw_candidates = sum(len(r.get("gliner_candidates", [])) for r in members) # how many total candidates
    kept_candidates = sum(len(drop_junk(r)) for r in members) # how many candidates survive junk filtering
    candidate_quality = survival_ratio(kept_candidates, raw_candidates)
    if coverage == 0.0 and not cluster.indicators:
        return None
    # total score is a weighted sum of coverage(how many types of entities), support(how many records and indicators), and survival ratio of candidates
    score = weighted_sum({"coverage": (coverage, 0.45), "support": (support, 0.35), "candidate_quality": (candidate_quality, 0.20)})
    return to_percent(clamp_score(score))


def compute_indicator_confidence(extraction_score: float | None, corroborating_mentions: int = 1) -> int | None:
    extraction_component = extraction_score if extraction_score is not None else 0.4
    corroboration_component = capped_ratio(corroborating_mentions, 3)
    score = weighted_sum({
        "extraction": (extraction_component, 0.7),
        "corroboration": (corroboration_component, 0.3),
    })
    return to_percent(clamp_score(score))