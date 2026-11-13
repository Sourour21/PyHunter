from math import ceil, log2
from pathlib import Path
import warnings

import yaml


def load_rules(rules_path: str | Path | None = None) -> dict:
    """
    Load PyHunter detection rules from a YAML file.
    """

    if rules_path is None:
        project_root = Path(__file__).resolve().parents[2]
        rules_path = project_root / "rules" / "detection_rules.yaml"

    rules_path = Path(rules_path)

    if not rules_path.is_file():
        raise FileNotFoundError(f"Rules file not found: {rules_path}")

    with rules_path.open("r", encoding="utf-8-sig") as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError("Invalid YAML configuration.")

    rules = config.get("detection_rules")

    if not isinstance(rules, dict) or not rules:
        raise ValueError("Missing or invalid 'detection_rules' section.")

    check_dns_rule(rules.get("suspicious_dns"))

    return rules


def check_dns_rule(rule: dict | None) -> None:
    """Warn when the DNS entropy threshold can never be reached.

    A label of n characters has a Shannon entropy of at most log2(n), so
    labels shorter than 2 ** entropy_threshold can never trigger an alert.
    """

    if not isinstance(rule, dict):
        return

    threshold = rule.get("entropy_threshold")
    minimum_length = rule.get("minimum_label_length")

    if not threshold or not minimum_length:
        return

    if log2(minimum_length) < threshold:
        effective = ceil(2 ** threshold)
        warnings.warn(
            f"suspicious_dns: labels of {minimum_length} characters have a "
            f"maximum entropy of {log2(minimum_length):.2f} < "
            f"{threshold}; only labels of {effective}+ characters "
            f"can trigger an alert.",
            stacklevel=2,
        )


if __name__ == "__main__":
    rules = load_rules()

    print("\nPyHunter - Detection Rules Loader")
    print(f"Loaded rules: {len(rules)}")

    for name, settings in rules.items():
        print(f"\nRule: {name}")
        print(f"Enabled: {settings.get('enabled')}")
        print(f"Severity: {settings.get('severity')}")
