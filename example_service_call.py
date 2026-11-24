from api import evaluate_family_decision

if __name__ == "__main__":
    result = evaluate_family_decision(
        {"category": "schedule", "value": "tired"},
        config_path="family_config.yaml",
        actor="parent",
    )
    print(result)
