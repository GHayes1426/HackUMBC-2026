"""
Plugin core: the Check base class and the registry.

Every security check subclasses Check and is decorated with
@register. The decorator appends the class to REGISTRY, and
run_all() instantiates and runs each one. app.py only ever calls
run_all(), which is why adding a check never requires touching
app.py or the HTML template.

Result contract returned by Check.run():
    {
        "status":  "ok" | "warning" | "error",
        "summary": "Short headline",
        "items":   [{"label": str, "status": str, "detail": str}, ...],
    }
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


def run_all():
    """
    Run every registered check and return a list of result dicts,
    each extended with the check's name and description so the
    template can render a panel without knowing about Check classes.

    A check that raises is reported as an "error" panel instead of
    taking down the whole page.
    """
    results = []
    for cls in REGISTRY:
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
