"""
Threat Summary: condenses every check's results into the numbers and
bars shown at the top of the dashboard.

Not a Check. app.py calls build_summary(run_all()). It only reads the
standard result dicts, so new checks are counted automatically. A
check can also contribute a chart by adding an optional "chart" key:
    {"title": str, "note": str, "bars": [{"label", "value", "flagged"}]}
A bar can instead carry "tone" (any item status) to pick its color.

Counting: "warning" (RISK) and "review" (REVIEW) items are potential
threats; "info" (IN USE) items are expected and not counted as threats.
"""

# Display order and labels for every item status; the template's color key uses this too.
STATUSES = [
    ("warning", "Risk", "Something dangerous is open or turned off, or an attack sign was found. Fix these first."),
    ("review", "Review", "Probably needed, but worth a look: a risky port an app uses, or an unrecognized program other devices can reach."),
    ("info", "In use", "A recognized app or OS feature needs this port. Normal; close it only if you don't use that feature."),
    ("ok", "Safe", "Closed, only reachable from this computer, or a protection that's turned on."),
    ("error", "Unknown", "Couldn't be checked on this system, usually because it needs admin rights."),
]


def _with_widths(bars):
    """Add "pct" (bar length relative to the largest value) for the template."""
    top = max((bar["value"] for bar in bars), default=0) or 1
    return [{**bar, "pct": round(bar["value"] / top * 100, 1)} for bar in bars]


def _count(items, status):
    return sum(1 for item in items if item["status"] == status)


def build_summary(results):
    all_items = [item for r in results for item in r["items"]]
    categories = []
    for r in results:
        risks, reviews = _count(r["items"], "warning"), _count(r["items"], "review")
        categories.append({
            "name": r["name"],
            "status": r["status"],
            "risks": risks,
            "reviews": reviews,
            "in_use": _count(r["items"], "info"),
            "findings": risks + reviews,
        })

    charts = [
        {
            "id": "by-check",
            "title": "Potential threats by check",
            "note": "Risk + review items in each check",
            "bars": _with_widths([
                {"label": c["name"], "value": c["findings"],
                 "tone": "warning" if c["risks"] else "review" if c["reviews"] else "ok"}
                for c in categories
            ]),
        },
        {
            "id": "by-status",
            "title": "Everything checked, by status",
            "note": f"{len(all_items)} items across {len(results)} checks",
            "bars": _with_widths([
                {"label": label, "value": _count(all_items, status), "tone": status}
                for status, label, _ in STATUSES
            ]),
        },
    ]
    for r in results:
        if r.get("chart") and r["chart"]["bars"]:
            charts.append({**r["chart"], "bars": _with_widths(r["chart"]["bars"])})

    return {
        "total": sum(c["findings"] for c in categories),
        "risks": _count(all_items, "warning"),
        "reviews": _count(all_items, "review"),
        "in_use": _count(all_items, "info"),
        "checks_clear": sum(1 for c in categories if c["status"] in ("ok", "info")),
        "categories": categories,
        "charts": charts,
        "statuses": STATUSES,
        "tags": {status: label for status, label, _ in STATUSES},
    }
