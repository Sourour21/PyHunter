from pathlib import Path
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

    return rules


if __name__ == "__main__":
    rules = load_rules()

    print("\nPyHunter - Detection Rules Loader")
    print(f"Loaded rules: {len(rules)}")

    for name, settings in rules.items():
        print(f"\nRule: {name}")
        print(f"Enabled: {settings.get('enabled')}")
        print(f"Severity: {settings.get('severity')}")
