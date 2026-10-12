"""Deterministic ranking of structurally valid, still unproved strategies."""
from copy import deepcopy


def rank_strategies(candidates):
    """Discard invalid candidates before ranking; retain exact resource identity.

    Evidence coverage and unresolved questions precede complexity. Ranking is
    advisory and never changes Context authority or grants generation permission.
    """
    valid = []
    for candidate in candidates:
        validation = candidate.get("validation", {})
        if validation.get("valid") is not True or validation.get("status") != "structurally_valid":
            continue
        strategy = candidate.get("strategy", {})
        if strategy.get("generation_allowed") is not False or validation.get("generation_allowed") is not False:
            continue
        metrics = validation.get("metrics", {})
        count = max(1, metrics.get("step_count", 0))
        coverage = metrics.get("evidence_supported_steps", 0) / count
        key = (-coverage, metrics.get("hypothesis_count", 0), metrics.get("pending_semantic_count", 0),
            metrics.get("step_count", 0), -metrics.get("input_path_count", 0), strategy.get("strategy_digest", ""))
        valid.append((key, candidate))
    seen, ranked = set(), []
    for key, candidate in sorted(valid, key=lambda item: item[0]):
        identity = candidate["strategy"].get("strategy_digest")
        if not identity or identity in seen:
            continue
        seen.add(identity)
        row = deepcopy(candidate)
        row["rank"] = len(ranked) + 1
        row["ranking"] = {"evidence_coverage": -key[0], "hypothesis_count": key[1],
            "pending_semantic_count": key[2], "step_count": key[3], "input_path_count": -key[4],
            "generation_allowed": False}
        ranked.append(row)
    return ranked
