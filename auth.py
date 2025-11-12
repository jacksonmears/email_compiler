import sys
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def create_or_update_token(creds_file, token_path, token_file):
    creds = None
    full_token_path = os.path.join(token_path, token_file)
    os.makedirs(token_path, exist_ok=True)

    try:
        if os.path.exists(full_token_path):
            creds = Credentials.from_authorized_user_file(full_token_path, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(creds_file, SCOPES)
                creds = flow.run_local_server(port=0)

            with open(full_token_path, "w") as token:
                token.write(creds.to_json())
    except Exception as e:
        print(f"Error creating/updating token: {e}", file=sys.stderr)
        sys.exit(1)  # non-zero exit code signals error

    print(f"Token ready: {full_token_path}")

if __name__ == "__main__":
    try:
        num_emails = len([i for i in os.listdir("tokens")])
        add = int(input("Do you want to add an email(s)? Input the number you'd like to add: "))
    except ValueError:
        print("Invalid number", file=sys.stderr)
        sys.exit(2)

    for i in range(num_emails+add):
        create_or_update_token("credentials.json", "tokens", f"tokens{i}.json")
