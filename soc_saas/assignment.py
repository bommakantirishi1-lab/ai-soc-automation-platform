ANALYSTS = [
    "Sai Rishi Kumar Bommakanti",
    "Tier 1 Analyst",
    "Tier 2 Analyst"
]

current_index = 0


def assign_analyst():
    global current_index
    analyst = ANALYSTS[current_index]
    current_index = (current_index + 1) % len(ANALYSTS)
    return analyst