import requests
import json
import time
from typing import Dict, List, Optional

class ApigeeDebugManager:
“””
Manages Apigee debug sessions to capture API request/response data
“””

```
def __init__(self, org: str, env: str, access_token: str, base_url: str = "https://apigee.googleapis.com/v1"):
    """
    Initialize the Apigee Debug Manager
    
    Args:
        org: Apigee organization name
        env: Environment name (e.g., 'prod', 'test')
        access_token: OAuth access token for authentication
        base_url: Base URL for Apigee Management API
    """
    self.org = org
    self.env = env
    self.access_token = access_token
    self.base_url = base_url
    self.headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

def create_debug_session(self, api_proxy: str, revision: Optional[str] = None, 
                       timeout: int = 600, filter_condition: Optional[str] = None) -> Dict:
    """
    Create a debug session for an API proxy
    
    Args:
        api_proxy: Name of the API proxy
        revision: Specific revision number (optional, uses current if not specified)
        timeout: Session timeout in seconds (default: 600)
        filter_condition: Optional filter condition for the debug session
        
    Returns:
        Dict containing the debug session response
    """
    url = f"{self.base_url}/organizations/{self.org}/environments/{self.env}/apis/{api_proxy}/revisions/{revision or 'deployments'}/debugsessions"
    
    payload = {
        "timeout": timeout
    }
    
    if filter_condition:
        payload["filter"] = filter_condition
    
    response = requests.post(url, headers=self.headers, json=payload)
    response.raise_for_status()
    
    debug_session = response.json()
    print(f"✓ Debug session created: {debug_session.get('name')}")
    return debug_session

def list_debug_sessions(self, api_proxy: str, revision: Optional[str] = None) -> List[Dict]:
    """
    List all active debug sessions for an API proxy
    
    Args:
        api_proxy: Name of the API proxy
        revision: Specific revision number (optional)
        
    Returns:
        List of debug sessions
    """
    url = f"{self.base_url}/organizations/{self.org}/environments/{self.env}/apis/{api_proxy}/revisions/{revision or 'deployments'}/debugsessions"
    
    response = requests.get(url, headers=self.headers)
    response.raise_for_status()
    
    return response.json().get('sessions', [])

def get_debug_session_data(self, api_proxy: str, session_id: str, 
                          revision: Optional[str] = None) -> List[Dict]:
    """
    Retrieve debug session transaction data
    
    Args:
        api_proxy: Name of the API proxy
        session_id: Debug session ID
        revision: Specific revision number (optional)
        
    Returns:
        List of transaction data
    """
    url = f"{self.base_url}/organizations/{self.org}/environments/{self.env}/apis/{api_proxy}/revisions/{revision or 'deployments'}/debugsessions/{session_id}/data"
    
    response = requests.get(url, headers=self.headers)
    response.raise_for_status()
    
    return response.json()

def delete_debug_session(self, api_proxy: str, session_id: str, 
                       revision: Optional[str] = None) -> Dict:
    """
    Delete a debug session
    
    Args:
        api_proxy: Name of the API proxy
        session_id: Debug session ID
        revision: Specific revision number (optional)
        
    Returns:
        Dict containing the deletion response
    """
    url = f"{self.base_url}/organizations/{self.org}/environments/{self.env}/apis/{api_proxy}/revisions/{revision or 'deployments'}/debugsessions/{session_id}"
    
    response = requests.delete(url, headers=self.headers)
    response.raise_for_status()
    
    print(f"✓ Debug session deleted: {session_id}")
    return response.json()

def extract_request_response_data(self, transaction_data: Dict) -> Dict:
    """
    Extract relevant request/response information from transaction data
    
    Args:
        transaction_data: Raw transaction data from debug session
        
    Returns:
        Structured dict with request/response details
    """
    result = {
        "request": {
            "method": None,
            "path": None,
            "headers": {},
            "query_params": {},
            "body": None
        },
        "response": {
            "status_code": None,
            "headers": {},
            "body": None
        }
    }
    
    # Navigate through the debug data structure
    point = transaction_data.get('point', [])
    
    for p in point:
        point_id = p.get('id', '')
        
        # Extract request data
        if 'request' in point_id.lower() or point_id == 'Proxy Request':
            results = p.get('results', [])
            for r in results:
                if r.get('ActionResult') == 'request.verb':
                    result['request']['method'] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'request.uri':
                    result['request']['path'] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'request.header.names':
                    header_names = r.get('properties', {}).get('property', [])
                    for prop in header_names:
                        header_name = prop.get('value')
                        if header_name:
                            result['request']['headers'][header_name] = None
                elif 'request.header.' in r.get('ActionResult', ''):
                    header_name = r.get('ActionResult', '').replace('request.header.', '')
                    result['request']['headers'][header_name] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'request.queryparam.names':
                    param_names = r.get('properties', {}).get('property', [])
                    for prop in param_names:
                        param_name = prop.get('value')
                        if param_name:
                            result['request']['query_params'][param_name] = None
                elif 'request.queryparam.' in r.get('ActionResult', ''):
                    param_name = r.get('ActionResult', '').replace('request.queryparam.', '')
                    result['request']['query_params'][param_name] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'request.content':
                    result['request']['body'] = r.get('properties', {}).get('property', [{}])[0].get('value')
        
        # Extract response data
        if 'response' in point_id.lower() or point_id == 'Proxy Response':
            results = p.get('results', [])
            for r in results:
                if r.get('ActionResult') == 'response.status.code':
                    result['response']['status_code'] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'response.header.names':
                    header_names = r.get('properties', {}).get('property', [])
                    for prop in header_names:
                        header_name = prop.get('value')
                        if header_name:
                            result['response']['headers'][header_name] = None
                elif 'response.header.' in r.get('ActionResult', ''):
                    header_name = r.get('ActionResult', '').replace('response.header.', '')
                    result['response']['headers'][header_name] = r.get('properties', {}).get('property', [{}])[0].get('value')
                elif r.get('ActionResult') == 'response.content':
                    result['response']['body'] = r.get('properties', {}).get('property', [{}])[0].get('value')
    
    return result

def capture_api_traffic(self, api_proxy: str, revision: Optional[str] = None, 
                      wait_time: int = 30, max_transactions: int = 10) -> List[Dict]:
    """
    Create a debug session, wait for traffic, and capture transaction data
    
    Args:
        api_proxy: Name of the API proxy
        revision: Specific revision number (optional)
        wait_time: Time to wait for traffic in seconds
        max_transactions: Maximum number of transactions to capture
        
    Returns:
        List of extracted request/response data
    """
    print(f"\n🔍 Starting debug session for {api_proxy}...")
    
    # Create debug session
    session = self.create_debug_session(api_proxy, revision)
    session_id = session.get('name')
    
    print(f"⏳ Waiting {wait_time} seconds for traffic...")
    print(f"   (Make some API calls to {api_proxy} now)")
    time.sleep(wait_time)
    
    # Get debug data
    print(f"📊 Fetching debug data...")
    debug_data = self.get_debug_session_data(api_proxy, session_id, revision)
    
    # Extract transaction data
    transactions = []
    completed = debug_data.get('completed', [])[:max_transactions]
    
    for i, transaction in enumerate(completed, 1):
        print(f"   Processing transaction {i}/{len(completed)}...")
        extracted = self.extract_request_response_data(transaction)
        transactions.append(extracted)
    
    # Clean up
    self.delete_debug_session(api_proxy, session_id, revision)
    
    print(f"✓ Captured {len(transactions)} transactions\n")
    return transactions
```

# Example usage

if **name** == “**main**”:
# Configuration
ORG = “your-org-name”
ENV = “test”
API_PROXY = “your-api-proxy”
ACCESS_TOKEN = “your-access-token”

```
# Initialize manager
manager = ApigeeDebugManager(ORG, ENV, ACCESS_TOKEN)

# Capture API traffic
transactions = manager.capture_api_traffic(
    api_proxy=API_PROXY,
    revision=None,  # Use current deployment
    wait_time=30,
    max_transactions=5
)

# Display results
for i, transaction in enumerate(transactions, 1):
    print(f"Transaction {i}:")
    print(json.dumps(transaction, indent=2))
    print("-" * 80)
```