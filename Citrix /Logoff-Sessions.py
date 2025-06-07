import re
import json
import requests

# File path
file_path = '/var/ossec/logs/citrix.json'


client_id = 'xxxxxd40-0a90-4fdf-ac22-d4ade14axxxx'
client_secret = 'IPByxJINROgVTH25-Jic0w=='
token_url = 'https://api.cloud.com/cctrustoauth2/eyc02mbk31li/tokens/clients'
customer_id = 'eyc02mbk31li'
site_id = 'a0ed6544-3944-4c36-8f18-75a5e3ba17b2'



# Regex patterns
server_type_pattern = r'"server-type"\s*:\s*"CitrixServers"'
parent_user_pattern = r'"parentUser":"(.*?)"'

# Function to get bearer token
def get_bearer_token():
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        print("Requesting bearer token...")
        response = requests.post(token_url, headers=headers, data=data)
        response.raise_for_status()
        token = response.json().get('access_token')
        print(f"Token obtained: {token[:10]}... (truncated)")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining token: {e}")
        return None

# Function to search sessions by user
def search_sessions_by_user(bearer_token, username):
    request_uri = "https://api.cloud.com/cvad/manage/Sessions/$search"
    headers = {
        'Authorization': f'CWSAuth Bearer={bearer_token}',
        'Citrix-CustomerId': customer_id,
        'Citrix-InstanceId': site_id,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    payload = json.dumps({
        "SearchFilters": [
            {
                "Property": "CurrentUser",
                "Value": username,
                "Operator": "Like"
            }
        ]
    })
    try:
        print(f"Searching sessions for user: {username}")
        response = requests.post(request_uri, headers=headers, verify=False, data=payload)
        response.raise_for_status()
        result = response.json()
        print(f"Session search response: {json.dumps(result, indent=4)}")
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error searching sessions: {e}")
        return None

# Function to log off session
def logoff_session(bearer_token, session_id):
    request_uri = f"https://api.cloud.com/cvad/manage/Sessions/{session_id}/$logoff"
    headers = {
        'Authorization': f'CWSAuth Bearer={bearer_token}',
        'Citrix-CustomerId': customer_id,
        'Citrix-InstanceId': site_id,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    try:
        print(f"Logging off session ID: {session_id}")
        response = requests.post(request_uri, headers=headers)
        response.raise_for_status()
        result = response.json()
        print(f"Logoff response: {json.dumps(result, indent=4)}")
        return result
    except requests.exceptions.RequestException as e:
        print(f"Error logging off session: {e}")
        return None

# Read the JSON file
try:
    with open(file_path, 'r') as file:
        json_data = file.read()

    # Check if server-type is CitrixServers
    server_type_match = re.search(server_type_pattern, json_data)

    if server_type_match:
        # Extract all parent users
        parent_users = re.findall(parent_user_pattern, json_data)
        clean_parent_users = [user.replace('domain\\', '') for user in parent_users if user.startswith('domain\\')]

        # Obtain bearer token
        bearer_token = get_bearer_token()

        if bearer_token and clean_parent_users:
            for user in clean_parent_users:
                print(f"Checking sessions for user: {user}")
                result = search_sessions_by_user(bearer_token, user)

                if result and 'Items' in result:
                    for session in result['Items']:
                        session_id = session.get('Id')
                        if session_id:
                            logoff_result = logoff_session(bearer_token, session_id)
                            print(f"Logged off user {user} from session {session_id}")
                else:
                    print(f"No active sessions found for user {user}")
        else:
            print("No valid parent users found or failed to obtain token")
    else:
        print("Server type is not CitrixServers")

except FileNotFoundError:
    print(f"File not found: {file_path}")
except json.JSONDecodeError:
    print("Error decoding JSON data")
except Exception as e:
    print(f"An error occurred: {e}")

