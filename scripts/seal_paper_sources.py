from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fmb.core.paper_integrity import source_files


def main():
    rows = source_files({"package": ROOT / "src/fmb"})
    record = {
        "schema_version": "paper_source_manifest.v1",
        "implementation_version": "0.6.0",
        "historical_rules_adapter": "shared_native_rules.v2",
        "historical_rule_module_version": 7,
        "historical_lock_sha256": "e4c6d4ae515a5d263d1d7fe05580e0265835c2bb6ac1d3f7b9e4bcd64582dac8",
        "files": {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in rows.items()
        },
    }
    (ROOT / "src/fmb/paper-source-manifest.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    print(
        json.dumps(
            {
                "bound_files": len(rows),
                "status": "sealed_current_implementation_requires_validation",
            }
        )
    )


if __name__ == "__main__":
    main()
