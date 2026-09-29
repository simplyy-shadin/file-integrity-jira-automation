from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def hmac_hex(key: bytes, value: Any) -> str:
    return hmac.new(
        key,
        canonical_json(value),
        hashlib.sha256,
    ).hexdigest()


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
