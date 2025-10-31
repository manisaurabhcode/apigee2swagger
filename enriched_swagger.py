import json
import re
import xml.etree.ElementTree as ET
import requests
import time
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict

class ApigeeDebugManager:
“””
Manages Apigee debug sessions to capture live API request/response data
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

def get_debug_session_data(self, api_proxy: str, session_id: str, 
                          revision: Optional[str] = None) -> Dict:
    """
    Retrieve debug session transaction data
    
    Args:
        api_proxy: Name of the API proxy
        session_id: Debug session ID
        revision: Specific revision number (optional)
        
    Returns:
        Dict containing transaction data
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
                action_result = r.get('ActionResult', '')
                properties = r.get('properties', {}).get('property', [])
                value = properties[0].get('value') if properties else None
                
                if action_result == 'request.verb':
                    result['request']['method'] = value
                elif action_result == 'request.uri':
                    result['request']['path'] = value
                elif 'request.header.' in action_result:
                    header_name = action_result.replace('request.header.', '')
                    result['request']['headers'][header_name] = value
                elif 'request.queryparam.' in action_result:
                    param_name = action_result.replace('request.queryparam.', '')
                    result['request']['query_params'][param_name] = value
                elif action_result == 'request.content':
                    result['request']['body'] = value
        
        # Extract response data
        if 'response' in point_id.lower() or point_id == 'Proxy Response':
            results = p.get('results', [])
            for r in results:
                action_result = r.get('ActionResult', '')
                properties = r.get('properties', {}).get('property', [])
                value = properties[0].get('value') if properties else None
                
                if action_result == 'response.status.code':
                    result['response']['status_code'] = value
                elif 'response.header.' in action_result:
                    header_name = action_result.replace('response.header.', '')
                    result['response']['headers'][header_name] = value
                elif action_result == 'response.content':
                    result['response']['body'] = value
    
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

class ApigeeToOpenAPI:
“”“Convert Apigee API Proxy to OpenAPI 2.0 specification with comprehensive coverage”””

```
def __init__(self, proxy_location: str, debug_manager: Optional[ApigeeDebugManager] = None):
    """
    Initialize converter with proxy location
    
    Args:
        proxy_location: Path to the extracted Apigee proxy directory
        debug_manager: Optional ApigeeDebugManager for capturing live traffic
    """
    self.location = Path(proxy_location)
    self.debug_manager = debug_manager
    self.openapi_json = {}
    self.definitions = {}
    self.security_definitions = {}
    self.tags = []
    self.consumes = set()
    self.produces = set()
    self.captured_traffic = []

def load_xml(self, file_path: Path) -> Optional[ET.Element]:
    """Load and parse XML file"""
    try:
        tree = ET.parse(file_path)
        return tree.getroot()
    except Exception as e:
        print(f"Error loading XML {file_path}: {e}")
        return None

def get_text(self, element: Optional[ET.Element], default: str = '') -> str:
    """Safely get text from XML element"""
    if element is not None and element.text:
        return element.text.strip()
    return default

def get_attribute(self, element: Optional[ET.Element], attr: str, default: str = '') -> str:
    """Safely get attribute from XML element"""
    if element is not None:
        return element.get(attr, default)
    return default

def capture_live_traffic(self, api_proxy: str, revision: Optional[str] = None,
                       wait_time: int = 30, max_transactions: int = 10):
    """
    Capture live API traffic using debug sessions
    
    Args:
        api_proxy: Name of the API proxy
        revision: Specific revision number
        wait_time: Time to wait for traffic
        max_transactions: Maximum number of transactions to capture
    """
    if not self.debug_manager:
        print("❌ Debug manager not configured. Initialize with ApigeeDebugManager.")
        return
    
    self.captured_traffic = self.debug_manager.capture_api_traffic(
        api_proxy=api_proxy,
        revision=revision,
        wait_time=wait_time,
        max_transactions=max_transactions
    )

def enrich_with_captured_traffic(self):
    """
    Enrich OpenAPI spec with data from captured traffic
    """
    if not self.captured_traffic:
        print("No captured traffic to enrich specification")
        return
    
    print(f"\n📈 Enriching spec with {len(self.captured_traffic)} captured transactions...")
    
    for transaction in self.captured_traffic:
        request = transaction.get('request', {})
        response = transaction.get('response', {})
        
        method = request.get('method', '').lower()
        path = request.get('path', '')
        
        if not method or not path:
            continue
        
        # Normalize path to match OpenAPI format
        normalized_path = self._normalize_path_for_matching(path)
        
        # Find matching path in spec
        matched_path = self._find_matching_path(normalized_path)
        
        if not matched_path:
            # Create new path entry
            matched_path = normalized_path
            if matched_path not in self.openapi_json['paths']:
                self.openapi_json['paths'][matched_path] = {}
        
        # Initialize operation if doesn't exist
        if method not in self.openapi_json['paths'][matched_path]:
            self.openapi_json['paths'][matched_path][method] = {
                'operationId': f"{method}_{matched_path.replace('/', '_')}",
                'responses': {},
                'parameters': []
            }
        
        operation = self.openapi_json['paths'][matched_path][method]
        
        # Add query parameters
        for param_name, param_value in request.get('query_params', {}).items():
            if not any(p['name'] == param_name and p['in'] == 'query' 
                      for p in operation['parameters']):
                operation['parameters'].append({
                    'name': param_name,
                    'in': 'query',
                    'required': False,
                    'type': 'string',
                    'description': f'Captured from live traffic'
                })
        
        # Add header parameters (selective - common headers)
        common_headers = ['authorization', 'x-api-key', 'content-type', 'accept']
        for header_name, header_value in request.get('headers', {}).items():
            if header_name.lower() in common_headers:
                if not any(p['name'] == header_name and p['in'] == 'header' 
                          for p in operation['parameters']):
                    operation['parameters'].append({
                        'name': header_name,
                        'in': 'header',
                        'required': False,
                        'type': 'string',
                        'description': f'Captured from live traffic'
                    })
        
        # Add response
        status_code = response.get('status_code', '200')
        if status_code not in operation['responses']:
            operation['responses'][status_code] = {
                'description': f'Response from live traffic capture'
            }
        
        # Detect content types from body
        if request.get('body'):
            self._detect_body_content_type(request['body'], 'request')
        if response.get('body'):
            self._detect_body_content_type(response['body'], 'response')
    
    print("✓ Enrichment complete")

def _normalize_path_for_matching(self, path: str) -> str:
    """
    Normalize path from actual request to OpenAPI format
    Replace actual IDs with {id} parameters
    """
    # Remove query string if present
    if '?' in path:
        path = path.split('?')[0]
    
    parts = path.split('/')
    normalized_parts = []
    
    for part in parts:
        # Check if part looks like an ID (UUID, number, etc.)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.I):
            normalized_parts.append('{id}')
        elif re.match(r'^\d+$', part):
            normalized_parts.append('{id}')
        else:
            normalized_parts.append(part)
    
    return '/'.join(normalized_parts)

def _find_matching_path(self, path: str) -> Optional[str]:
    """Find matching path in existing OpenAPI spec"""
    if path in self.openapi_json.get('paths', {}):
        return path
    
    # Try to find similar path with parameters
    for existing_path in self.openapi_json.get('paths', {}).keys():
        if self._paths_match(path, existing_path):
            return existing_path
    
    return None

def _paths_match(self, path1: str, path2: str) -> bool:
    """Check if two paths match (considering parameters)"""
    parts1 = path1.split('/')
    parts2 = path2.split('/')
    
    if len(parts1) != len(parts2):
        return False
    
    for p1, p2 in zip(parts1, parts2):
        if p1 == p2:
            continue
        if p1.startswith('{') and p1.endswith('}'):
            continue
        if p2.startswith('{') and p2.endswith('}'):
            continue
        return False
    
    return True

def _detect_body_content_type(self, body: str, body_type: str):
    """Detect content type from body content"""
    if not body:
        return
    
    body_stripped = body.strip()
    
    if body_stripped.startswith('{') or body_stripped.startswith('['):
        if body_type == 'request':
            self.consumes.add('application/json')
        else:
            self.produces.add('application/json')
    elif body_stripped.startswith('<'):
        if body_type == 'request':
            self.consumes.add('application/xml')
        else:
            self.produces.add('application/xml')

def generate_openapi(self, api_name: str, proxy_endpoint: str, 
                    proxy_xml_file: str = "default.xml",
                    include_target_endpoints: bool = True,
                    capture_live_traffic: bool = False,
                    traffic_wait_time: int = 30) -> Dict[str, Any]:
    """
    Generate OpenAPI specification from Apigee proxy
    
    Args:
        api_name: Name of the API proxy
        proxy_endpoint: Full URL of the proxy endpoint
        proxy_xml_file: Name of the proxy endpoint XML file (default: "default.xml")
        include_target_endpoints: Whether to process target endpoints
        capture_live_traffic: Whether to capture live API traffic
        traffic_wait_time: Time to wait for traffic capture
        
    Returns:
        Dictionary containing OpenAPI specification
    """
    self.openapi_json = {
        "swagger": "2.0",
        "info": {},
        "paths": {}
    }
    
    # Load main API proxy XML
    api_xml_path = self.location / "apiproxy" / f"{api_name}.xml"
    api_root = self.load_xml(api_xml_path)
    
    if api_root is None:
        print(f"Could not load API proxy XML: {api_xml_path}")
        return self.openapi_json
    
    # Parse Info Section
    self._parse_info_section(api_root, api_name)
    
    # Parse Host & Schemes
    self._parse_host_and_schemes(proxy_endpoint)
    
    # Load ProxyEndpoint XML
    proxy_xml_path = self.location / "apiproxy" / "proxies" / proxy_xml_file
    proxy_root = self.load_xml(proxy_xml_path)
    
    if proxy_root is None:
        print(f"Could not load proxy endpoint XML: {proxy_xml_path}")
        return self.openapi_json
    
    # Parse BasePath
    self._parse_base_path(proxy_root)
    
    # Parse security from proxy
    self._parse_security(proxy_root)
    
    # Parse Flows (paths and operations)
    self._parse_flows(proxy_root, flow_type='proxy')
    
    # Process all proxy endpoints
    self._process_all_proxy_endpoints(api_name)
    
    # Process target endpoints if requested
    if include_target_endpoints:
        self._process_target_endpoints()
    
    # Capture live traffic if requested
    if capture_live_traffic and self.debug_manager:
        self.capture_live_traffic(
            api_proxy=api_name,
            wait_time=traffic_wait_time
        )
        self.enrich_with_captured_traffic()
    
    # Add global consumes/produces
    if self.consumes:
        self.openapi_json['consumes'] = sorted(list(self.consumes))
    if self.produces:
        self.openapi_json['produces'] = sorted(list(self.produces))
    
    # Add definitions if any
    if self.definitions:
        self.openapi_json['definitions'] = self.definitions
    
    # Add security definitions if any
    if self.security_definitions:
        self.openapi_json['securityDefinitions'] = self.security_definitions
    
    # Add tags if any
    if self.tags:
        self.openapi_json['tags'] = self.tags
    
    return self.openapi_json

def _parse_info_section(self, root: ET.Element, api_name: str):
    """Parse API info section with contact and license"""
    description_elem = root.find('Description')
    version_elem = root.get('revision', '1')
    display_name_elem = root.find('DisplayName')
    created_by_elem = root.find('CreatedBy')
    
    self.openapi_json['info'] = {
        'description': self.get_text(description_elem),
        'version': f"{version_elem}.0.0",
        'title': self.get_text(display_name_elem, api_name)
    }
    
    # Add contact if available
    if created_by_elem is not None:
        created_by = self.get_text(created_by_elem)
        if created_by:
            self.openapi_json['info']['contact'] = {'email': created_by}

def _parse_host_and_schemes(self, proxy_endpoint: str):
    """Parse host and protocol schemes"""
    parsed_url = urlparse(proxy_endpoint)
    self.openapi_json['host'] = parsed_url.netloc or ''
    
    protocol = parsed_url.scheme or 'http'
    self.openapi_json['schemes'] = [protocol]

def _parse_base_path(self, root: ET.Element):
    """Parse base path from proxy endpoint"""
    try:
        base_path_elem = root.find('.//HTTPProxyConnection/BasePath')
        if base_path_elem is not None:
            self.openapi_json['basePath'] = self.get_text(base_path_elem)
    except Exception as e:
        print(f"Error parsing base path: {e}")

def _parse_security(self, root: ET.Element):
    """Parse security policies to generate security definitions"""
    flows = root.findall('.//PreFlow') + root.findall('.//PostFlow')
    
    for flow in flows:
        steps = flow.findall('.//Step')
        for step in steps:
            step_name = self.get_text(step.find('Name'))
            if step_name:
                self._check_security_policy(step_name)

def _check_security_policy(self, policy_name: str):
    """Check if a policy is a security policy and add to definitions"""
    policy_path = self.location / "apiproxy" / "policies" / f"{policy_name}.xml"
    policy_root = self.load_xml(policy_path)
    
    if policy_root is None:
        return
    
    # OAuth policies
    if policy_root.tag == 'OAuthV2':
        operation = self.get_text(policy_root.find('Operation'))
        if operation in ['VerifyAccessToken', 'ValidateAccessToken']:
            self.security_definitions['OAuth2'] = {
                'type': 'oauth2',
                'flow': 'accessCode',
                'authorizationUrl': 'https://example.com/oauth/authorize',
                'tokenUrl': 'https://example.com/oauth/token',
                'scopes': {}
            }
    
    # API Key policies
    elif policy_root.tag == 'VerifyAPIKey':
        api_key_elem = policy_root.find('.//APIKey')
        if api_key_elem is not None:
            ref = api_key_elem.get('ref', 'request.header.x-api-key')
            key_name = 'x-api-key'
            key_location = 'header'
            
            if 'header' in ref.lower():
                match = re.search(r'header\.([^}]+)', ref)
                if match:
                    key_name = match.group(1)
                key_location = 'header'
            elif 'queryparam' in ref.lower():
                match = re.search(r'queryparam\.([^}]+)', ref)
                if match:
                    key_name = match.group(1)
                key_location = 'query'
            
            self.security_definitions['ApiKeyAuth'] = {
                'type': 'apiKey',
                'name': key_name,
                'in': key_location
            }
    
    # Basic Auth
    elif policy_root.tag == 'BasicAuthentication':
        self.security_definitions['BasicAuth'] = {
            'type': 'basic'
        }
    
    # JWT policies
    elif policy_root.tag in ['VerifyJWT', 'GenerateJWT']:
        self.security_definitions['BearerAuth'] = {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT Bearer token'
        }

def _parse_flows(self, root: ET.Element, flow_type: str = 'proxy'):
    """Parse flows to extract paths and operations"""
    flows = root.findall('.//Flows/Flow')
    
    for flow in flows:
        condition_elem = flow.find('Condition')
        if condition_elem is None:
            continue
        
        condition = self.get_text(condition_elem)
        
        # Extract verb and path
        resource_verb, resource_path = self._extract_verb_and_path(condition)
        
        if not resource_verb or not resource_path:
            continue
        
        # Initialize path in OpenAPI spec
        if resource_path not in self.openapi_json['paths']:
            self.openapi_json['paths'][resource_path] = {}
        
        # Initialize operation
        operation = {
            'operationId': flow.get('name', ''),
            'responses': {},
            'parameters': []
        }
        
        # Add description/summary
        description_elem = flow.find('Description')
        if description_elem is not None:
            operation['summary'] = self.get_text(description_elem)
        
        # Add tags
        tag = self._extract_tag_from_path(resource_path)
        if tag:
            operation['tags'] = [tag]
            if tag not in [t['name'] for t in self.tags]:
                self.tags.append({'name': tag})
        
        # Extract path parameters
        self._extract_path_parameters(resource_path, operation)
        
        # Extract parameters and responses from policies
        self._extract_policy_parameters(flow, operation, 'Request')
        self._extract_policy_responses(flow, operation)
        
        # Ensure at least one response
        if not operation['responses']:
            operation['responses']['200'] = {'description': 'successful operation'}
        
        self.openapi_json['paths'][resource_path][resource_verb] = operation

def _extract_verb_and_path(self, condition: str) -> tuple:
    """Extract HTTP verb and path from condition"""
    resource_verb = ''
    resource_path = ''
    
    verb_match = re.search(r'request\.verb\s*[=!]+\s*"([^"]+)"', condition)
    if not verb_match:
        verb_match = re.search(r'request\.method\s*[=!]+\s*"([^"]+)"', condition)
    
    path_match = re.search(r'proxy\.pathsuffix\s+MatchesPath\s+"([^"]+)"', condition)
    if not path_match:
        path_match = re.search(r'proxy\.pathsuffix\s*[=~]+\s*"([^"]+)"', condition)
    if not path_match:
        path_match = re.search(r'proxy\.path\s*[=~]+\s*"([^"]+)"', condition)
    
    if verb_match:
        resource_verb = verb_match.group(1).lower()
    
    if path_match:
        resource_path = path_match.group(1)
    
    return resource_verb, resource_path

def _extract_tag_from_path(self, path: str) -> str:
    """Extract tag from path"""
    parts = path.strip('/').split('/')
    if parts and parts[0]:
        tag = re.sub(r'\{.*?\}', '', parts[0]).strip()
        return tag if tag else None
    return None

def _extract_path_parameters(self, path: str, operation: Dict[str, Any]):
    """Extract path parameters from path template"""
    path_params = re.findall(r'\{([^}]+)\}', path)
    
    for param_name in path_params:
        parameter = {
            'name': param_name,
            'in': 'path',
            'required': True,
            'type': 'string',
            'description': f'Path parameter: {param_name}'
        }
        operation['parameters'].append(parameter)

def _extract_policy_parameters(self, flow: ET.Element, operation: Dict[str, Any], 
                               flow_section: str = 'Request'):
    """Extract parameters from policies in the flow"""
    section_elem = flow.find(flow_section)
    if section_elem is None:
        return
    
    steps = section_elem.findall('Step')
    for step in steps:
        step_name = self.get_text(step.find('Name'))
        if not step_name:
            continue
        
        policy_path = self.location / "apiproxy" / "policies" / f"{step_name}.xml"
        policy_root = self.load_xml(policy_path)
        
        if policy_root is None:
            continue
        
        if policy_root.tag == 'ExtractVariables':
            self._process_extract_variables_policy(policy_root, operation)
        elif policy_root.tag == 'AssignMessage':
            self._process_assign_message_policy(policy_root, operation)
        elif policy_root.tag in ['JSONToXML', 'XMLToJSON']:
            self._detect_content_types(policy_root)
        elif policy_root.tag == 'RaiseFault':
            self._process_raise_fault_policy(policy_root, operation)

def _extract_policy_responses(self, flow: ET.Element, operation: Dict[str, Any]):
    """Extract response information from Response flow policies"""
    response_elem = flow.find('Response')
    if response_elem is None:
        return
    
    steps = response_elem.findall('Step')
    for step in steps:
        step_name = self.get_text(step.find('Name'))
        if not step_name:
            continue
        
        policy_path = self.location / "apiproxy" / "policies" / f"{step_name}.xml"
        policy_root = self.load_xml(policy_path)
        
        if policy_root is None:
            continue
        
        if policy_root.tag == 'AssignMessage':
            self._process_response_assign_message(policy_root, operation)
        elif policy_root.tag in ['JSONToXML', 'XMLToJSON']:
            self._detect_content_types(policy_root)

def _process_extract_variables_policy(self, policy_root: ET.Element, 
                                     operation: Dict[str, Any]):
    """Process ExtractVariables policy"""
    source_elem = policy_root.find('Source')
    source = self.get_text(source_elem, 'request')
    
    if source == 'request':
        # Headers
        self._add_params_from_extract_variables(
            policy_root.findall('Header'), 'header', operation
        )
        # Query params
        self._add_params_from_extract_variables(
            policy_root.findall('QueryParam'), 'query', operation
        )
        # Form params
        self._add_params_from_extract_variables(
            policy_root.findall('FormParam'), 'formData', operation
        )
        # JSONPath (body parameters)
        json_paths = policy_root.findall('JSONPayload/Variable')
        if json_paths:
            self._add_body_parameter(operation, 'application/json')
        
        # XMLPayload
        xml_paths = policy_root.findall('XMLPayload/Variable')
        if xml_paths:
            self._add_body_parameter(operation, 'application/xml')

def _process_assign_message_policy(self, policy_root: ET.Element, 
                                  operation: Dict[str, Any]):
    """Process AssignMessage policy for request body"""
    payload_elem = policy_root.find('.//Payload')
    if payload_elem is not None:
        content_type = payload_elem.get('contentType', 'application/json')
        self._add_body_parameter(operation, content_type)
        self.consumes.add(content_type)

def _process_response_assign_message(self, policy_root: ET.Element, 
                                    operation: Dict[str, Any]):
    """Process AssignMessage policy in response flow"""
    status_code_elem = policy_root.find('.//StatusCode')
    status_code = self.get_text(status_code_elem, '200')
    
    payload_elem = policy_root.find('.//Payload')
    description = 'successful operation'
    
    if payload_elem is not None:
        content_type = payload_elem.get('contentType', 'application/json')
        self.produces.add(content_type)
        description = f'Response with {content_type}'
    
    operation['responses'][status_code] = {'description': description}

def _process_raise_fault_policy(self, policy_root: ET.Element, 
                               operation: Dict[str, Any]):
    """Process RaiseFault policy for error responses"""
    fault_response = policy_root.find('FaultResponse')
    if fault_response is not None:
        status_code_elem = fault_response.find('.//StatusCode')
        reason_elem = fault_response.find('.//ReasonPhrase')
        
        status_code = self.get_text(status_code_elem, '400')
        description = self.get_text(reason_elem, 'Error response')
        
        operation['responses'][status_code] = {'description': description}

def _add_params_from_extract_variables(self, param_elements: List[ET.Element], 
                                      param_type: str, operation: Dict[str, Any]):
    """Add parameters from ExtractVariables policy elements"""
    for param_elem in param_elements:
        param_name = param_elem.get('name')
        if not param_name:
            continue
        
        if any(p['name'] == param_name and p['in'] == param_type 
               for p in operation['parameters']):
            continue
        
        default_elem = param_elem.find('DefaultValue')
        pattern_elem = param_elem.find('Pattern')
        
        parameter = {
            'name': param_name,
            'in': param_type,
            'required': default_elem is None,
            'type': 'string'
        }
        
        if default_elem is not None:
            parameter['default'] = self.get_text(default_elem)
        
        if pattern_elem is not None:
            parameter['description'] = f'Pattern: {self.get_text(pattern_elem)}'
        
        operation['parameters'].append(parameter)

def _add_body_parameter(self, operation: Dict[str, Any], content_type: str):
    """Add body parameter to operation"""
    if any(p.get('in') == 'body' for p in operation['parameters']):
        return
    
    parameter = {
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object'
        }
    }
    
    operation['parameters'].append(parameter)
    self.consumes.add(content_type)

def _detect_content_types(self, policy_root: ET.Element):
    """Detect content types from conversion policies"""
    if policy_root.tag == 'JSONToXML':
        self.consumes.add('application/json')
        self.produces.add('application/xml')
    elif policy_root.tag == 'XMLToJSON':
        self.consumes.add('application/xml')
        self.produces.add('application/json')

def _process_all_proxy_endpoints(self, api_name: str):
    """Process all proxy endpoint files"""
    proxies_dir = self.location / "apiproxy" / "proxies"
    if not proxies_dir.exists():
        return
    
    for proxy_file in proxies_dir.glob("*.xml"):
        if proxy_file.name == "default.xml":
            continue
        
        proxy_root = self.load_xml(proxy_file)
        if proxy_root is not None:
            self._parse_flows(proxy_root, flow_type='proxy')

def _process_target_endpoints(self):
    """Process target endpoints for backend information"""
    targets_dir = self.location / "apiproxy" / "targets"
    if not targets_dir.exists():
        return
    
    for target_file in targets_dir.glob("*.xml"):
        target_root = self.load_xml(target_file)
        if target_root is not None:
            http_target = target_root.find('.//HTTPTargetConnection/URL')
            if http_target is not None:
                backend_url = self.get_text(http_target)
                if 'info' in self.openapi_json:
                    if 'x-backend-services' not in self.openapi_json['info']:
                        self.openapi_json['info']['x-backend-services'] = []
                    self.openapi_json['info']['x-backend-services'].append({
                        'name': target_file.stem,
                        'url': backend_url
                    })

def save_to_file(self, output_name: Optional[str] = None):
    """Save OpenAPI spec to JSON file"""
    if output_name is None:
        output_name = "openapi"
    
    output_path = self.location / f"{output_name}.json"
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.openapi_json, f, indent=2, ensure_ascii=False)
        print(f"OpenAPI JSON successfully generated: {output_path}")
        return str(output_path)
    except Exception as e:
        print(f"Error writing JSON file: {e}")
        return None

def validate_spec(self) -> List[str]:
    """Basic validation of generated OpenAPI spec"""
    warnings = []
    
    if not self.openapi_json.get('paths'):
        warnings.append("No paths found in specification")
    
    if not self.openapi_json.get('host'):
        warnings.append("No host defined")
    
    if not self.openapi_json.get('basePath'):
        warnings.append("No basePath defined")
    
    for path, methods in self.openapi_json.get('paths', {}).items():
        for method, operation in methods.items():
            if not operation.get('responses'):
                warnings.append(f"No responses defined for {method.upper()} {path}")
    
    return warnings
```

# Usage Examples

if **name** == “**main**”:
# ===== Example 1: Generate OpenAPI from Apigee Proxy Only =====
print(”=” * 80)
print(“Example 1: Generate OpenAPI from Apigee Proxy Files”)
print(”=” * 80)

```
proxy_location = "/path/to/apigee-proxy"
api_name = "my-api"
proxy_endpoint = "https://api.example.com"

converter = ApigeeToOpenAPI(proxy_location)
openapi_spec = converter.generate_openapi(
    api_name=api_name,
    proxy_endpoint=proxy_endpoint,
    proxy_xml_file="default.xml",
    include_target_endpoints=True
)

warnings = converter.validate_spec()
if warnings:
    print("\nValidation warnings:")
    for warning in warnings:
        print(f"  - {warning}")

converter.save_to_file(output_name=api_name)

print(f"\nGenerated OpenAPI spec with:")
print(f"  - {len(openapi_spec.get('paths', {}))} paths")
print(f"  - {len(openapi_spec.get('definitions', {}))} definitions")
print(f"  - {len(openapi_spec.get('securityDefinitions', {}))} security schemes")

# ===== Example 2: Enrich with Live Traffic Capture =====
print("\n" + "=" * 80)
print("Example 2: Enrich OpenAPI with Live Traffic Data")
print("=" * 80)

# Configuration
ORG = "your-org"
ENV = "test"
ACCESS_TOKEN = "your-access-token"
API_NAME = "my-api"
PROXY_LOCATION = "/path/to/apigee-proxy"
PROXY_ENDPOINT = "https://api.example.com"

# Initialize debug manager
debug_mgr = ApigeeDebugManager(ORG, ENV, ACCESS_TOKEN)

# Initialize converter with debug manager
converter_with_debug = ApigeeToOpenAPI(PROXY_LOCATION, debug_manager=debug_mgr)

# Generate OpenAPI with live traffic capture
enriched_spec = converter_with_debug.generate_openapi(
    api_name=API_NAME,
    proxy_endpoint=PROXY_ENDPOINT,
    capture_live_traffic=True,
    traffic_wait_time=30  # Wait 30 seconds for traffic
)

converter_with_debug.save_to_file(output_name=f"{API_NAME}_enriched")

print(f"\nEnriched OpenAPI spec with:")
print(f"  - {len(enriched_spec.get('paths', {}))} paths")
print(f"  - {len(converter_with_debug.captured_traffic)} captured transactions")

# ===== Example 3: Standalone Traffic Capture =====
print("\n" + "=" * 80)
print("Example 3: Capture Traffic Without OpenAPI Generation")
print("=" * 80)

debug_mgr_standalone = ApigeeDebugManager(ORG, ENV, ACCESS_TOKEN)

# Just capture traffic
transactions = debug_mgr_standalone.capture_api_traffic(
    api_proxy=API_NAME,
    wait_time=30,
    max_transactions=10
)

# Display captured data
print("\nCaptured Transactions:")
for i, txn in enumerate(transactions, 1):
    print(f"\nTransaction {i}:")
    print(f"  Method: {txn['request']['method']}")
    print(f"  Path: {txn['request']['path']}")
    print(f"  Query Params: {txn['request']['query_params']}")
    print(f"  Response Status: {txn['response']['status_code']}")

# Save captured traffic to file
with open('captured_traffic.json', 'w') as f:
    json.dump(transactions, f, indent=2)

print("\n✓ Captured traffic saved to captured_traffic.json")
```