"""X-VT-Anti-Abuse-Header generator."""

from __future__ import annotations

import base64
import random
import time


def compute_anti_abuse_header() -> str:
    """
    Generate the X-VT-Anti-Abuse-Header required by VirusTotal UI endpoints.

    Algorithm (reversed from vt-ui JS):
      1. current unix timestamp (float)
      2. random number roughly in range 1e10 .. 5e14
      3. concatenate: {random}-ZG9udCBiZSBldmls-{timestamp}
         (ZG9udCBiZSBldmls == base64("dont be evil"))
      4. base64-encode the whole string
    """
    timestamp = time.time()
    n = 1e10 * (1 + (random.random() % 5e4))
    raw = f"{n:.0f}-ZG9udCBiZSBldmls-{timestamp:.3f}"
    return base64.b64encode(raw.encode("utf-8")).decode("ascii")
