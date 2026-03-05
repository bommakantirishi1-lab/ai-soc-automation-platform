def generate_explanation(ip, events, severity):

    explanation = f"""
Threat Analysis

IP Address: {ip}

Observed Events:
{", ".join(events)}

Severity: {severity}

Explanation:
The sequence of events suggests potential suspicious behavior
within the environment.

Recommended Investigation Steps:

• Review authentication logs
• Inspect endpoint processes
• Monitor outbound network connections
"""

    return explanation