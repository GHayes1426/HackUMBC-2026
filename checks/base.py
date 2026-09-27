"""
Plugin core: the Check base class and the registry.

Every security check subclasses Check and is decorated with
@register. The decorator appends the class to REGISTRY, and
run_all() instantiates and runs each one. app.py only ever calls
run_all(), which is why adding a check never requires touching
app.py or the HTML template.

Result contract returned by Check.run():
    {
        "status":  <status>,           # overall: the worst item status
        "summary": "Short headline",
        "items":   [{"label": str, "status": <status>, "detail": str}, ...],
        "note":    "optional small print under the summary",
    }

Statuses (color and tag on the page, see checks/summary.py STATUSES):
    "warning" red    RISK     -- dangerous: fix it
    "review"  amber  REVIEW   -- probably needed or unrecognized: take a look
    "info"    blue   IN USE   -- a recognized app/OS feature needs it: normal
    "ok"      green  SAFE     -- closed, local-only, or protection on
    "error"   gray   UNKNOWN  -- couldn't be checked
"""

REGISTRY = []


class Check:
    NAME = "Unnamed check"
    DESCRIPTION = ""

    def run(self):
        """Perform the check and return a result dict (see module docstring)."""
        raise NotImplementedError


def register(cls):
    """Class decorator: add a Check subclass to the dashboard."""
    REGISTRY.append(cls)
    return cls


def run_all(names=None):
    """
    Run every registered check (or only those whose NAME is in names) and
    return a list of result dicts,
    each extended with the check's name and description so the
    template can render a panel without knowing about Check classes.

    A check that raises is reported as an "error" panel instead of
    taking down the whole page.
    """
    results = []
    for cls in REGISTRY:
        if names is not None and cls.NAME not in names:
            continue
        try:
            result = cls().run()
        except Exception as exc:
            result = {
                "status": "error",
                "summary": f"Check failed: {exc}",
                "items": [],
            }
        results.append({"name": cls.NAME, "description": cls.DESCRIPTION, **result})
    return results
