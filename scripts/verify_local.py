"""Repeat safe local checks and preserve exit codes/evidence.

Usage: python scripts/verify_local.py FRESH_OUTPUT_DIRECTORY
Requires admitted CPython and already installed Bandit/PyYAML. Never installs
packages; subprocesses run only inspected project checks, with timeouts.
"""

import ast
import json
from pathlib import Path
import re
# Fixed local check argument lists, no shell or content-selected command.
import subprocess  # nosec B404
import sys


def run_checks(output: Path):
    """Write logs/summary in a new folder; nonzero check outcomes are retained."""
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    checks = []
    for name, command in (
        ("tests", [sys.executable, "-m", "unittest", "discover", "-v"]),
        ("bandit", [sys.executable, "-m", "bandit", "-r", "opcode_inspector", "scripts",
                    "-f", "json", "-o", str(output.resolve() / "bandit.json")]),
        ("whitespace", ["git", "diff", "--check"]),
    ):
        try:
            # command comes only from the fixed check table above.
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=60, check=False)  # nosec B603
            (output / (name + ".log")).write_bytes(result.stdout + result.stderr)
            checks.append({"check": name, "status": "PASS" if result.returncode == 0 else "FAIL",
                           "exit_code": result.returncode, "command": command})
        except (OSError, subprocess.TimeoutExpired) as error:
            checks.append({"check": name, "status": "FAIL", "reason": str(error)})
    sources = list((root / "opcode_inspector").glob("*.py")) + list((root / "scripts").glob("*.py"))
    try:
        for path in sources:
            ast.parse(path.read_text(encoding="utf-8"))
        checks.append({"check": "syntax", "status": "PASS", "source_count": len(sources)})
    except (OSError, SyntaxError) as error:
        checks.append({"check": "syntax", "status": "FAIL", "reason": str(error)})
    try:
        import yaml
    except ImportError:
        checks.append({"check": "workflow policy", "status": "NOT RUN", "reason": "PyYAML not installed"})
    else:
        try:
            paths = list((root / ".github" / "workflows").glob("*.yml"))
            if len(paths) != 2:
                raise ValueError("Expected both workflow files")
            for path in paths:
                config = yaml.safe_load(path.read_text())
                # PyYAML's YAML 1.1 resolver parses the GitHub 'on' key as True.
                trigger = config.get("on", config.get(True))
                branches = (["main", "codex/pickle-opcode-inspector"] if path.stem == "checks" else ["main"])
                if trigger["push"]["branches"] != branches:
                    raise ValueError("Unexpected workflow branches")
                for job in config["jobs"].values():
                    for step in job["steps"]:
                        if "uses" in step and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]):
                            raise ValueError("Action is not pinned to an immutable SHA")
                        if step.get("uses", "").startswith("actions/checkout@"):
                            if step["with"]["persist-credentials"] is not False:
                                raise ValueError("Checkout credential persistence enabled")
            checks.append({"check": "workflow policy", "status": "PASS",
                           "note": "Local parse/pins/checkout policy, not hosted execution"})
        except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as error:
            checks.append({"check": "workflow policy", "status": "FAIL", "reason": str(error)})
    demos = []
    for name, expected in (("hello", 0), ("global-review", 1), ("trailing", 2)):
        try:
            # name comes only from the fixed three benign fixture names above.
            result = subprocess.run([sys.executable, "-m", "opcode_inspector", "examples/" + name + ".pkl",
                                     "--format", "json"], cwd=root, capture_output=True, timeout=10, check=False)  # nosec B603
            (output / ("demo-" + name + ".log")).write_bytes(result.stdout + result.stderr)
            demos.append({"fixture": name, "exit_code": result.returncode,
                          "expected_exit": expected, "report": json.loads(result.stdout)})
        except (OSError, subprocess.TimeoutExpired, ValueError) as error:
            demos.append({"fixture": name, "exit_code": None, "expected_exit": expected,
                          "error": str(error)})
    (output / "demo.json").write_text(json.dumps(demos, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    checks.append({"check": "demo CLI", "status": "PASS" if all(d["exit_code"] == d["expected_exit"]
                                                                             for d in demos) else "FAIL"})
    for name, reason in (("types/lint", "No configured checker or installed project tool established"),
                         ("Linux/hosted CI/CodeQL", "No hosted repository or Linux runtime run")):
        checks.append({"check": name, "status": "NOT RUN", "reason": reason})
    (output / "results.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
    return 1 if any(c["status"] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/verify_local.py FRESH_OUTPUT_DIRECTORY")
    raise SystemExit(run_checks(Path(sys.argv[1])))
