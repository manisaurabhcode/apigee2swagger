import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict


class ApigeeToOpenAPI:
    """Convert Apigee API Proxy to OpenAPI 2.0 specification with comprehensive coverage"""
    
    def __init__(self, proxy_location: str):
        """
        Initialize converter with proxy location
        
        Args:
            proxy_location: Path to the extracted Apigee proxy directory
        """
        self.location = Path(proxy_location)
        self.openapi_json = {}
        self.definitions = {}
        self.security_definitions = {}
        self.tags = []
        self.consumes = set()
        self.produces = set()
    
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
    
    def generate_openapi(self, api_name: str, proxy_endpoint: str, 
                        proxy_xml_file: str = "default.xml",
                        include_target_endpoints: bool = True) -> Dict[str, Any]:
        """
        Generate OpenAPI specification from Apigee proxy
        
        Args:
            api_name: Name of the API proxy
            proxy_endpoint: Full URL of the proxy endpoint
            proxy_xml_file: Name of the proxy endpoint XML file (default: "default.xml")
            include_target_endpoints: Whether to process target endpoints
            
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
        # Look for common security policy types in pre/post flows
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
                
                # Parse reference to determine location
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
            
            # Extract verb and path using multiple regex patterns
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
            
            # Add description/summary if available
            description_elem = flow.find('Description')
            if description_elem is not None:
                operation['summary'] = self.get_text(description_elem)
            
            # Add tags based on path
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
        """Extract HTTP verb and path from condition with multiple patterns"""
        resource_verb = ''
        resource_path = ''
        
        # Pattern 1: Standard format
        verb_match = re.search(r'request\.verb\s*[=!]+\s*"([^"]+)"', condition)
        path_match = re.search(r'proxy\.pathsuffix\s+MatchesPath\s+"([^"]+)"', condition)
        
        # Pattern 2: Alternative formats
        if not path_match:
            path_match = re.search(r'proxy\.pathsuffix\s*[=~]+\s*"([^"]+)"', condition)
        
        # Pattern 3: Direct path matching
        if not path_match:
            path_match = re.search(r'proxy\.path\s*[=~]+\s*"([^"]+)"', condition)
        
        # Pattern 4: MessageLogging or other patterns
        if not verb_match:
            verb_match = re.search(r'request\.method\s*[=!]+\s*"([^"]+)"', condition)
        
        if verb_match:
            resource_verb = verb_match.group(1).lower()
        
        if path_match:
            resource_path = path_match.group(1)
        
        return resource_verb, resource_path
    
    def _extract_tag_from_path(self, path: str) -> str:
        """Extract tag from path (first segment)"""
        parts = path.strip('/').split('/')
        if parts and parts[0]:
            # Remove path parameters
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
            
            # Load policy XML
            policy_path = self.location / "apiproxy" / "policies" / f"{step_name}.xml"
            policy_root = self.load_xml(policy_path)
            
            if policy_root is None:
                continue
            
            # ExtractVariables policy
            if policy_root.tag == 'ExtractVariables':
                self._process_extract_variables_policy(policy_root, operation)
            
            # AssignMessage policy (for request body)
            elif policy_root.tag == 'AssignMessage':
                self._process_assign_message_policy(policy_root, operation)
            
            # JSONToXML / XMLToJSON (content type detection)
            elif policy_root.tag in ['JSONToXML', 'XMLToJSON']:
                self._detect_content_types(policy_root)
            
            # RaiseFault (error responses)
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
            
            # AssignMessage in response (response structure)
            if policy_root.tag == 'AssignMessage':
                self._process_response_assign_message(policy_root, operation)
            
            # JSONToXML / XMLToJSON
            elif policy_root.tag in ['JSONToXML', 'XMLToJSON']:
                self._detect_content_types(policy_root)
    
    def _process_extract_variables_policy(self, policy_root: ET.Element, 
                                         operation: Dict[str, Any]):
        """Process ExtractVariables policy"""
        source_elem = policy_root.find('Source')
        source = 'request'  # Default
        
        if source_elem is not None:
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
        # Check for Payload assignment
        payload_elem = policy_root.find('.//Payload')
        if payload_elem is not None:
            content_type = payload_elem.get('contentType', 'application/json')
            self._add_body_parameter(operation, content_type)
            self.consumes.add(content_type)
    
    def _process_response_assign_message(self, policy_root: ET.Element, 
                                        operation: Dict[str, Any]):
        """Process AssignMessage policy in response flow"""
        # Check status code
        status_code_elem = policy_root.find('.//StatusCode')
        status_code = '200'
        
        if status_code_elem is not None:
            status_code = self.get_text(status_code_elem, '200')
        
        # Check payload
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
            
            # Check if parameter already exists
            if any(p['name'] == param_name and p['in'] == param_type 
                   for p in operation['parameters']):
                continue
            
            # Extract default value if available
            default_elem = param_elem.find('DefaultValue')
            pattern_elem = param_elem.find('Pattern')
            
            parameter = {
                'name': param_name,
                'in': param_type,
                'required': default_elem is None,  # Not required if has default
                'type': 'string'
            }
            
            if default_elem is not None:
                parameter['default'] = self.get_text(default_elem)
            
            if pattern_elem is not None:
                parameter['description'] = f'Pattern: {self.get_text(pattern_elem)}'
            
            operation['parameters'].append(parameter)
    
    def _add_body_parameter(self, operation: Dict[str, Any], content_type: str):
        """Add body parameter to operation"""
        # Check if body parameter already exists
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
                continue  # Already processed
            
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
                # Extract backend URL for documentation
                http_target = target_root.find('.//HTTPTargetConnection/URL')
                if http_target is not None:
                    backend_url = self.get_text(http_target)
                    # Could add this as x-backend-url extension
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
        
        # Check for operations without responses
        for path, methods in self.openapi_json.get('paths', {}).items():
            for method, operation in methods.items():
                if not operation.get('responses'):
                    warnings.append(f"No responses defined for {method.upper()} {path}")
        
        return warnings


# Usage Example
if __name__ == "__main__":
    # Configuration
    proxy_location = "/workspaces/codespaces-blank/apigee2openapi/apigee-proxy/api-platform-samples-master/sample-proxies/jira-release-notes"  # Path to extracted proxy
    api_name = "jira-release-notes"
    proxy_endpoint = "https://api.example.com/v1"
    
    # Generate OpenAPI spec
    converter = ApigeeToOpenAPI(proxy_location)
    openapi_spec = converter.generate_openapi(
        api_name=api_name,
        proxy_endpoint=proxy_endpoint,
        proxy_xml_file="default.xml",
        include_target_endpoints=True
    )
    
    # Validate
    warnings = converter.validate_spec()
    if warnings:
        print("\nValidation warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    
    # Save to file
    converter.save_to_file(output_name=api_name)
    
    # Print summary
    print(f"\nGenerated OpenAPI spec with:")
    print(f"  - {len(openapi_spec.get('paths', {}))} paths")
    print(f"  - {len(openapi_spec.get('definitions', {}))} definitions")
    print(f"  - {len(openapi_spec.get('securityDefinitions', {}))} security schemes")
    print(f"  - {len(openapi_spec.get('tags', []))} tags")
