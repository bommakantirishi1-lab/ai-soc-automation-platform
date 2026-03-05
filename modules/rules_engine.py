RULES = [
    {
        "name": "Brute Force Attack",
        "conditions": ["failed_login", "failed_login", "failed_login"],
        "score": 5
    },
    {
        "name": "Suspicious Login Sequence",
        "conditions": ["failed_login", "successful_login"],
        "score": 4
    },
    {
        "name": "Multi Stage Attack",
        "conditions": [
            "successful_login",
            "process_creation",
            "outbound_connection"
        ],
        "score": 8
    }
]


def evaluate_rules(events):

    triggered_rules = []

    for rule in RULES:

        if all(cond in events for cond in rule["conditions"]):
            triggered_rules.append(rule)

    return triggered_rules