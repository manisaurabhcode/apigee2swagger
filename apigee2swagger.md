##Interactive Mode
Convert directly from a ZIP or folder:
python apigee_to_openapi.py ./ApigeeBundle.zip --preview

WebUI
python apigee_to_openapi.py --ui


##Usage example
if __name__ == "__main__":
    proxy_location = "/path/to/apigee/proxy"
    api_name = "jira-release-notes"
    proxy_endpoint = "https://api.example.com/v1"

    converter = ApigeeToOpenAPI(proxy_location)
    openapi_spec = converter.generate_openapi(
        api_name=api_name,
        proxy_endpoint=proxy_endpoint,
        proxy_xml_file="default.xml",
        include_target_endpoints=True
    )

    converter.save_to_file(output_name=api_name)
