from __future__ import annotations

from contracts.types import ActionContext


def aggregate_risk(
    context: ActionContext,
    weights: dict[str, float] | None = None,
) -> tuple[float, dict[str, float]]:
    """Aggregate per-policy risk from standardized context.metadata entries.

    Collects every metadata value shaped like {"risk": float, "category": str,
    ...} (the shape all policies emit); anything else — plain kwargs, strings,
    dicts without both keys — is ignored. When two entries share a category
    the max wins. The total is the per-category sum, weighted by *weights*
    (default 1.0 per category) and capped at 1.0.

    Pure function of the context; safe to call at any point in the pipeline.
    Returns (risk_score, risk_categories) where risk_categories maps
    category -> unweighted per-category risk.
    """
    categories: dict[str, float] = {}
    for entry in context.metadata.values():
        if not isinstance(entry, dict):
            continue
        risk = entry.get("risk")
        category = entry.get("category")
        if not isinstance(risk, (int, float)) or isinstance(risk, bool):
            continue
        if not isinstance(category, str):
            continue
        clamped = min(1.0, max(0.0, float(risk)))
        categories[category] = max(categories.get(category, 0.0), clamped)

    weights = weights or {}
    total = sum(risk * weights.get(category, 1.0) for category, risk in categories.items())
    return round(min(1.0, total), 4), categories


class RiskScorer:
    """Writes the aggregated cross-policy risk back onto the ActionContext.

    SecureAgent runs this after all policies (allow path) and before raising
    ActionBlockedError (deny path), so every action carries a final
    risk_score. *weights* scales individual categories' contribution to the
    total (e.g. {"pii": 0.5} to down-weight redacted PII findings).
    """

    def __init__(self, weights: dict[str, float] | None = None) -> None:
        self._weights = dict(weights or {})

    def aggregate(self, context: ActionContext) -> ActionContext:
        context.risk_score, context.risk_categories = aggregate_risk(context, self._weights)
        return context
