from __future__ import annotations

import json
from sockpeek.models import InspectionResult


class JsonFormatter:
    """Renders InspectionResult as structured JSON."""

    def format(self, result: InspectionResult) -> str:
        return json.dumps(result.to_dict(), indent=2)