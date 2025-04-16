"""Allow running mqtt-audit as ``python -m mqtt_audit``."""

import sys

from mqtt_audit.cli import main

sys.exit(main())
