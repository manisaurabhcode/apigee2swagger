import json
import re
import yaml
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Set


class ApigeeToOpenAPI:
    """Convert Apigee API Proxy to OpenAPI 3.0 specification"""

    def __init__(self, proxy_location: str):
        self.location = Path(proxy_location)
        self.openapi_json = {}
        self.components = {
            'schemas': {},
            'securitySchemes': {}
        }
        self.tags = []
        self.consumes = set()
        self.produces = set()

    def load_xml(self, file_path: Path) -> Optional[ET.Element]:
        try:
            tree = ET.parse(file_path)
            return tree.getroot()
        except Exception as e:
            print(f"Error loading XML {file_path}: {e}")
            return None

    def get_text(self, element: Optional[ET.Element], default: str = '') -> str:
        return element.text.strip() if element is not None and element.text else default

    def generate_openapi(self, api_name: str, proxy_endpoint: str,
                         proxy_xml_file: str = "default.xml",
                         include_target_endpoints: bool = True) -> Dict[str, Any]:
        self.openapi_json = {
            "openapi": "3.0.3",
            "info": {},
            "paths": {},
            "components": self.components
        }

        # Load main proxy XML
        api_xml_path = self.location / "apiproxy" / f"{api_name}.xml"
        api_root = self.load_xml(api_xml_path)
        if api_root is None:
            print(f"Could not load API proxy XML: {api_xml_path}")
            return self.openapi_json

        # Parse Info
        self._parse_info_section(api_root, api_name)
        # Parse Servers
        self._parse_servers(proxy_endpoint)

        # ProxyEndpoint XML
        proxy_xml_path = self.location / "apiproxy" / "proxies" / proxy_xml_file
        proxy_root = self.load_xml(proxy_xml_path)
        if proxy_root is None:
            print(f"Could not load proxy endpoint XML: {proxy_xml_path}")
            return self.openapi_json

        # Base path
        self._parse_base_path(proxy_root)
        # Security
        self._parse_security(proxy_root)
        # Flows
        self._parse_flows(proxy_root)

        # Other proxy endpoints
        self._process_all_proxy_endpoints(api_name)

        # Target endpoints
        if include_target_endpoints:
            self._process_target_endpoints()

        # Tags
        if self.tags:
            self.openapi_json['tags'] = self.tags

        return self.openapi_json

    def _parse_info_section(self, root: ET.Element, api_name: str):
        description_elem = root.find('Description')
        version = root.get('revision', '1')
        display_name_elem = root.find('DisplayName')
        created_by_elem = root.find('CreatedBy')

        info = {
            'title': self.get_text(display_name_elem, api_name),
            'version': f"{version}.0.0",
            'description': self.get_text(description_elem)
        }
        if created_by_elem is not None:
            created_by = self.get_text(created_by_elem)
            if created_by:
                info['contact'] = {'email': created_by}

        self.openapi_json['info'] = info

    def _parse_servers(self, proxy_endpoint: str):
        parsed_url = urlparse(proxy_endpoint)
        server_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        self.openapi_json['servers'] = [{'url': server_url}]

    def _parse_base_path(self, root: ET.Element):
        base_path_elem = root.find('.//HTTPProxyConnection/BasePath')
        if base_path_elem is not None:
            base_path = self.get_text(base_path_elem)
            if base_path:
                for srv in self.openapi_json.get('servers', []):
                    srv['url'] += base_path

    def _parse_security(self, root: ET.Element):
        flows = root.findall('.//PreFlow') + root.findall('.//PostFlow')
        for flow in flows:
            steps = flow.findall('.//Step')
            for step in steps:
                step_name = self.get_text(step.find('Name'))
                if step_name:
                    self._check_security_policy(step_name)

    def _check_security_policy(self, policy_name: str):
        policy_path = self.location / "apiproxy" / "policies" / f"{policy_name}.xml"
        policy_root = self.load_xml(policy_path)
        if policy_root is None:
            return

        if policy_root.tag == 'OAuthV2':
            self.components['securitySchemes']['OAuth2'] = {
                'type': 'oauth2',
                'flows': {
                    'authorizationCode': {
                        'authorizationUrl': 'https://example.com/oauth/authorize',
                        'tokenUrl': 'https://example.com/oauth/token',
                        'scopes': {}
                    }
                }
            }
        elif policy_root.tag == 'VerifyAPIKey':
            self.components['securitySchemes']['ApiKeyAuth'] = {
                'type': 'apiKey',
                'name': 'x-api-key',
                'in': 'header'
            }
        elif policy_root.tag == 'BasicAuthentication':
            self.components['securitySchemes']['BasicAuth'] = {'type': 'http', 'scheme': 'basic'}
        elif policy_root.tag in ['VerifyJWT', 'GenerateJWT']:
            self.components['securitySchemes']['BearerAuth'] = {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT'
            }

    def _parse_flows(self, root: ET.Element):
        flows = root.findall('.//Flows/Flow')
        for flow in flows:
            condition_elem = flow.find('Condition')
            if condition_elem is None:
                continue
            condition = self.get_text(condition_elem)
            verb, path = self._extract_verb_and_path(condition)
            if not verb or not path:
                continue

            if path not in self.openapi_json['paths']:
                self.openapi_json['paths'][path] = {}

            operation = {
                'operationId': flow.get('name', ''),
                'responses': {},
                'parameters': []
            }

            desc = flow.find('Description')
            if desc is not None:
                operation['summary'] = self.get_text(desc)

            tag = self._extract_tag_from_path(path)
            if tag:
                operation['tags'] = [tag]
                if tag not in [t['name'] for t in self.tags]:
                    self.tags.append({'name': tag})

            self._extract_path_parameters(path, operation)
            self._extract_policy_parameters(flow, operation)
            self._extract_policy_responses(flow, operation)

            if not operation['responses']:
                operation['responses']['200'] = {'description': 'successful operation'}

            # Move body parameters to requestBody (OpenAPI 3)
            body_params = [p for p in operation['parameters'] if p.get('in') == 'body']
            if body_params:
                content_type = self.consumes.pop() if self.consumes else 'application/json'
                operation['requestBody'] = {
                    'content': {
                        content_type: {'schema': body_params[0].get('schema', {'type': 'object'})}
                    },
                    'required': True
                }
                operation['parameters'] = [p for p in operation['parameters'] if p.get('in') != 'body']

            self.openapi_json['paths'][path][verb] = operation

    def _extract_verb_and_path(self, condition: str) -> tuple:
        verb_match = re.search(r'request\.verb\s*[=!]+\s*"([^"]+)"', condition)
        path_match = re.search(r'proxy\.pathsuffix\s+MatchesPath\s+"([^"]+)"', condition)
        if not path_match:
            path_match = re.search(r'proxy\.path\s*[=~]+\s*"([^"]+)"', condition)
        return (verb_match.group(1).lower() if verb_match else None,
                path_match.group(1) if path_match else None)

    def _extract_tag_from_path(self, path: str) -> str:
        parts = path.strip('/').split('/')
        if parts and parts[0]:
            tag = re.sub(r'\{.*?\}', '', parts[0]).strip()
            return tag or None
        return None

    def _extract_path_parameters(self, path: str, operation: Dict[str, Any]):
        path_params = re.findall(r'\{([^}]+)\}', path)
        for p in path_params:
            operation['parameters'].append({
                'name': p,
                'in': 'path',
                'required': True,
                'schema': {'type': 'string'},
                'description': f'Path parameter: {p}'
            })

    def _extract_policy_parameters(self, flow: ET.Element, operation: Dict[str, Any]):
        request_elem = flow.find('Request')
        if request_elem is None:
            return
        steps = request_elem.findall('Step')
        for step in steps:
            step_name = self.get_text(step.find('Name'))
            if not step_name:
                continue
            policy_path = self.location / "apiproxy" / "policies" / f"{step_name}.xml"
            policy_root = self.load_xml(policy_path)
            if policy_root is None:
                continue
            if policy_root.tag == 'AssignMessage':
                payload_elem = policy_root.find('.//Payload')
                if payload_elem is not None:
                    content_type = payload_elem.get('contentType', 'application/json')
                    self._add_body_parameter(operation, content_type)
            elif policy_root.tag == 'ExtractVariables':
                self._add_body_parameter(operation, 'application/json')

    def _extract_policy_responses(self, flow: ET.Element, operation: Dict[str, Any]):
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
                status_elem = policy_root.find('.//StatusCode')
                status_code = self.get_text(status_elem, '200')
                payload_elem = policy_root.find('.//Payload')
                desc = 'successful operation'
                if payload_elem is not None:
                    ctype = payload_elem.get('contentType', 'application/json')
                    desc = f'Response with {ctype}'
                operation['responses'][status_code] = {'description': desc}

    def _add_body_parameter(self, operation: Dict[str, Any], content_type: str):
        if any(p.get('in') == 'body' for p in operation['parameters']):
            return
        operation['parameters'].append({
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {'type': 'object'}
        })
        self.consumes.add(content_type)

    def _process_all_proxy_endpoints(self, api_name: str):
        proxies_dir = self.location / "apiproxy" / "proxies"
        if not proxies_dir.exists():
            return
        for proxy_file in proxies_dir.glob("*.xml"):
            if proxy_file.name == "default.xml":
                continue
            proxy_root = self.load_xml(proxy_file)
            if proxy_root is not None:
                self._parse_flows(proxy_root)

    def _process_target_endpoints(self):
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
                        self.openapi_json['info'].setdefault('x-backend-services', [])
                        self.openapi_json['info']['x-backend-services'].append({
                            'name': target_file.stem,
                            'url': backend_url
                        })

    def save_to_file(self, output_name: Optional[str] = None):
        """Save OpenAPI spec to JSON and YAML"""
        if output_name is None:
            output_name = "openapi"
        json_path = self.location / f"{output_name}.json"
        yaml_path = self.location / f"{output_name}.yaml"

        try:
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(self.openapi_json, f, indent=2, ensure_ascii=False)
            with open(yaml_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.openapi_json, f, sort_keys=False)
            print(f"✅ OpenAPI 3.0 files generated:\n  - {json_path}\n  - {yaml_path}")
            return str(json_path), str(yaml_path)
        except Exception as e:
            print(f"Error saving files: {e}")
            return None, None
