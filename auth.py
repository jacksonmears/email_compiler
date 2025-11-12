from __future__ import print_function
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Gmail read-only scope for token generation
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def create_or_update_token(creds_file, token_path, token_file):
    """
    Creates or refreshes a Gmail OAuth token for a user.
    Saves the token to `token_path/token_file`.
    """
    creds = None

    # Ensure the token folder exists
    os.makedirs(token_path, exist_ok=True)
    full_token_path = os.path.join(token_path, token_file)

    # Load existing token if it exists
    if os.path.exists(full_token_path):
        creds = Credentials.from_authorized_user_file(full_token_path, SCOPES)

    # If no valid credentials, refresh or generate new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(creds_file, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the token for future use
        with open(full_token_path, "w") as token:
            token.write(creds.to_json())

    print(f"Token ready: {full_token_path}")

if __name__ == "__main__":
    # Prompt user for exactly one number (digits only)
    num_emails = int(input("Input the number of emails you would like to add to the compiler: "))

    # Generate token files for each account
    for i in range(num_emails):
        create_or_update_token("credentials.json", "tokens", f"tokens{i}.json")
