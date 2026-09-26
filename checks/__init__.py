"""
Importing a check module is what registers it (via @register), so
this file is the one list of which checks appear on the dashboard.
Panels appear in the order they are imported here.

To add a check: create checks/your_check.py, then add one line below.
"""

from checks import port_scan  # noqa: F401
from checks import ioc_analyzer  # noqa: F401
