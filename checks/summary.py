"""
Threat Summary: condenses every check's results into the numbers and
bars shown at the top of the dashboard.

Not a Check. app.py calls build_summary(run_all()). It only reads the
standard result dicts, so new checks are counted automatically. A
check can also contribute a chart by adding an optional "chart" key:
    {"title": str, "note": str, "bars": [{"label", "value", "flagged"}]}
"""


def _with_widths(bars):
    """Add "pct" (bar length relative to the largest value) for the template."""
    top = max((bar["value"] for bar in bars), default=0) or 1
    return [{**bar, "pct": round(bar["value"] / top * 100, 1)} for bar in bars]


def build_summary(results):
    categories = [
        {
            "name": r["name"],
            "status": r["status"],
            "findings": sum(1 for item in r["items"] if item["status"] == "warning"),
        }
        for r in results
    ]

    charts = [{
        "title": "Potential threats by category",
        "note": "Flagged items in each check",
        "bars": _with_widths([
            {"label": c["name"], "value": c["findings"], "flagged": c["findings"] > 0}
            for c in categories
        ]),
    }]
    for r in results:
        if r.get("chart") and r["chart"]["bars"]:
            charts.append({**r["chart"], "bars": _with_widths(r["chart"]["bars"])})

    return {
        "total": sum(c["findings"] for c in categories),
        "checks_clear": sum(1 for c in categories if c["status"] == "ok"),
        "categories": categories,
        "charts": charts,
    }
