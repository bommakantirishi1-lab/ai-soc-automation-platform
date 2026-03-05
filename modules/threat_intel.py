import requests

ABUSE_API = "https://api.abuseipdb.com/api/v2/check"


def check_abuseip(ip, api_key=None):

    if not api_key:
        return 0

    try:

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        r = requests.get(ABUSE_API, headers=headers, params=params)

        if r.status_code != 200:
            return 0

        score = r.json()["data"]["abuseConfidenceScore"]

        return int(score / 10)

    except Exception:
        return 0