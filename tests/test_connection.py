import os
import pytest
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("DEVIN_API_KEY")
ORG_ID = os.getenv("DEVIN_ORG_ID")

@pytest.mark.skip(reason="Live Devin API test — run manually: pytest tests/test_connection.py")
def test_connection():
    # Step 1 — check env vars are loaded
    print(f"API Key: {'set' if API_KEY else 'MISSING'}")
    print(f"Org ID: {'set' if ORG_ID else 'MISSING'}")
    
    if not API_KEY or not ORG_ID:
        print("ERROR: Missing env vars. Check your .env file.")
        return

    # Step 2 — create a minimal test session
    print("\nCreating test session...")
    response = requests.post(
        f"https://api.devin.ai/v3/organizations/{ORG_ID}/sessions",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },
        json={"prompt": "Say hello and do nothing else."}
    )

    print(f"Status code: {response.status_code}")
    print(f"Response: {response.json()}")

    # Step 3 — confirm session_id returned
    if response.status_code == 200:
        session_id = response.json().get("session_id")
        print(f"\nSUCCESS — session_id: {session_id}")
    else:
        print("\nFAILED — check your API key and org ID")

if __name__ == "__main__":
    test_connection()