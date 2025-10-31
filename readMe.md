🎯 Key Features
1. OpenAPI Generation from Apigee Proxy Files (Your Original Code)
	•	Parses Apigee proxy XML files
	•	Extracts paths, operations, parameters, responses
	•	Handles security policies (OAuth, API Key, JWT, Basic Auth)
	•	Processes ExtractVariables, AssignMessage, RaiseFault policies
	•	Supports multiple proxy and target endpoints
2. Live Traffic Capture via Debug Sessions (New)
	•	Creates debug sessions using Apigee Management API
	•	Captures real API request/response data
	•	Extracts:
	•	HTTP methods and paths
	•	Query parameters
	•	Headers
	•	Request/response bodies
	•	Status codes
3. Enrichment (Merged Functionality)
	•	Enriches OpenAPI spec with captured traffic data
	•	Adds missing query parameters from real requests
	•	Detects actual header usage
	•	Validates paths against live traffic
	•	Auto-detects content types from actual payloads


Example 1: Generate OpenAPI from Files Only
converter = ApigeeToOpenAPI("/path/to/proxy")
spec = converter.generate_openapi(
    api_name="my-api",
    proxy_endpoint="https://api.example.com"
)
converter.save_to_file()


Example 2: Enrich with Live Traffic

# Setup debug manager
debug_mgr = ApigeeDebugManager(
    org="your-org",
    env="test", 
    access_token="your-token"
)

# Generate with traffic capture
converter = ApigeeToOpenAPI("/path/to/proxy", debug_manager=debug_mgr)
spec = converter.generate_openapi(
    api_name="my-api",
    proxy_endpoint="https://api.example.com",
    capture_live_traffic=True,
    traffic_wait_time=30
)

Example 3: Capture Traffic Only
debug_mgr = ApigeeDebugManager(org, env, token)
transactions = debug_mgr.capture_api_traffic(
    api_proxy="my-api",
    wait_time=30
)


