"""Dynamic source-code inspector that reads actual running module code with line numbers."""

from pathlib import Path
from typing import Dict, List, Any

MODULES_DIR = Path(__file__).resolve().parent / "modules"


def extract_code_section(filename: str, start_marker: str, end_marker: str) -> Dict[str, Any]:
    """Read lines between markers from the actual Python module file on disk."""
    filepath = MODULES_DIR / filename
    if not filepath.exists():
        return {"file": f"app/modules/{filename}", "start_line": 0, "end_line": 0, "lines": []}

    all_lines = filepath.read_text(encoding="utf-8").splitlines()
    start_idx = None
    end_idx = None

    for idx, line in enumerate(all_lines):
        if start_marker in line and start_idx is None:
            start_idx = idx + 1
        elif end_marker in line and start_idx is not None:
            end_idx = idx
            break

    if start_idx is None:
        return {"file": f"app/modules/{filename}", "start_line": 0, "end_line": 0, "lines": []}
    if end_idx is None:
        end_idx = len(all_lines)

    extracted: List[Dict[str, Any]] = []
    for i in range(start_idx, end_idx):
        extracted.append({"num": i + 1, "code": all_lines[i]})

    return {
        "file": f"app/modules/{filename}",
        "start_line": start_idx + 1,
        "end_line": end_idx,
        "lines": extracted,
    }


def get_module_source_pair(filename: str) -> Dict[str, Any]:
    """Return both the actual vulnerable and secured code paths for a module."""
    return {
        "vulnerable": extract_code_section(filename, "# [SOURCE_INSPECT:VULNERABLE_START]", "# [SOURCE_INSPECT:VULNERABLE_END]"),
        "secured": extract_code_section(filename, "# [SOURCE_INSPECT:SECURED_START]", "# [SOURCE_INSPECT:SECURED_END]"),
    }
