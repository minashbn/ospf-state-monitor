
import re


def clean_state(state_str: str) -> str:
    if not state_str:
        return ""

    first_part = state_str.split("/")[0]
    cleaned = re.sub(r"[^a-zA-Z]", "", first_part)
    return cleaned.lower()