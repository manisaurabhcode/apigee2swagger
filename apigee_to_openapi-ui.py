import os
import sys
import zipfile
import json
import yaml
import tempfile
import webbrowser
from pathlib import Path
from flask import Flask, request, render_template_string, send_file

# ==============================
#  Apigee → OpenAPI Converter
# ==============================
class ApigeeToOpenAPI:
    def __init__(self, input_path: str):
        self.input_path = Path(input_path)
        self.temp_dir = None

    def extract_zip(self):
        if zipfile.is_zipfile(self.input_path):
            self.temp_dir = Path(tempfile.mkdtemp())
            with zipfile.ZipFile(self.input_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            print(f"📦 Extracted ZIP to {self.temp_dir}")
            return self.temp_dir
        elif self.input_path.is_dir():
            return self.input_path
        else:
            raise ValueError("Input must be a zip file or a directory")

    def find_proxy_files(self, base_path):
        files = list(base_path.rglob("*.xml"))
        if not files:
            raise FileNotFoundError("No XML files found in Apigee bundle")
        return files

    def convert_to_openapi(self):
        # Placeholder: minimal structure — extend per Apigee XML content
        openapi = {
            "openapi": "3.0.3",
            "info": {"title": "Converted Apigee Proxy", "version": "1.0.0"},
            "paths": {"/example": {"get": {"summary": "Sample endpoint", "responses": {"200": {"description": "OK"}}}}},
        }
        return openapi

    def save_to_file(self, openapi_data, output_name="openapi"):
        json_path = Path(f"{output_name}.json")
        yaml_path = Path(f"{output_name}.yaml")

        with open(json_path, "w") as jf:
            json.dump(openapi_data, jf, indent=2)
        with open(yaml_path, "w") as yf:
            yaml.dump(openapi_data, yf, sort_keys=False)

        print(f"✅ Saved:\n - {json_path}\n - {yaml_path}")
        return json_path, yaml_path


# ==============================
# Swagger Preview (local)
# ==============================
def preview_swagger_ui(spec_path: str, port=5000):
    app = Flask(__name__)
    spec_file = Path(spec_path)

    @app.route("/openapi.yaml")
    @app.route("/openapi.yml")
    @app.route("/openapi.json")
    def serve_spec():
        return send_file(spec_file)

    @app.route("/")
    def swagger_ui():
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8" />
            <title>Swagger UI - {spec_file.name}</title>
            <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
        </head>
        <body>
            <div id="swagger-ui"></div>
            <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
            <script>
                const ui = SwaggerUIBundle({{
                    url: '/openapi{spec_file.suffix}',
                    dom_id: '#swagger-ui',
                    presets: [SwaggerUIBundle.presets.apis],
                    layout: "BaseLayout"
                }});
            </script>
        </body>
        </html>
        """

    webbrowser.open(f"http://127.0.0.1:{port}")
    app.run(port=port, debug=False)


# ==============================
# Web Upload UI
# ==============================
def launch_ui():
    app = Flask(__name__)
    upload_dir = Path(tempfile.mkdtemp())

    TEMPLATE = """
    {% raw %}
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Apigee → OpenAPI Converter</title>
        <style>
            body { font-family: sans-serif; margin: 40px; }
            h2 { color: #333; }
            .box { border: 2px dashed #bbb; padding: 20px; border-radius: 12px; width: 400px; }
        </style>
    </head>
    <body>
        <h2>Apigee Proxy → OpenAPI Converter</h2>
        <form action="/convert" method="post" enctype="multipart/form-data" class="box">
            <input type="file" name="file" accept=".zip" required><br><br>
            <button type="submit">Convert</button>
        </form>
        {% endraw %}
        {% if swagger_url %}
            <p>✅ Conversion complete!</p>
            <a href="{{ swagger_url }}" target="_blank">Open Swagger UI Preview</a>
        {% endif %}
    {% raw %}
    </body>
    </html>
    {% endraw %}
    """


    @app.route("/", methods=["GET"])
    def index():
        return render_template_string(TEMPLATE, swagger_url=None)

    @app.route("/convert", methods=["POST"])
    def convert():
        file = request.files["file"]
        if not file or not file.filename.endswith(".zip"):
            return "Invalid file. Please upload a .zip.", 400

        zip_path = upload_dir / file.filename
        file.save(zip_path)
        converter = ApigeeToOpenAPI(zip_path)
        base_path = converter.extract_zip()
        _ = converter.find_proxy_files(base_path)
        openapi_data = converter.convert_to_openapi()
        _, yaml_path = converter.save_to_file(openapi_data, output_name=upload_dir / "openapi")

        swagger_url = f"/swagger/{yaml_path.name}"
        return render_template_string(TEMPLATE, swagger_url=swagger_url)

    @app.route("/swagger/<filename>")
    def swagger(filename):
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8" />
            <title>Swagger UI - {filename}</title>
            <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
        </head>
        <body>
            <div id="swagger-ui"></div>
            <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
            <script>
                const ui = SwaggerUIBundle({{
                    url: '/files/{filename}',
                    dom_id: '#swagger-ui'
                }});
            </script>
        </body>
        </html>
        """

    @app.route("/files/<filename>")
    def serve_file(filename):
        return send_file(upload_dir / filename)

    print("🌐 Web UI running at http://127.0.0.1:5000")
    webbrowser.open("http://127.0.0.1:5000")
    app.run(port=5000, debug=False)


# ==============================
# Command-line Entry Point
# ==============================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert Apigee proxy bundles to OpenAPI 3.0 spec.")
    parser.add_argument("input", nargs="?", help="Path to Apigee bundle (zip or folder).")
    parser.add_argument("--preview", action="store_true", help="Preview Swagger UI after conversion.")
    parser.add_argument("--ui", action="store_true", help="Launch simple web UI.")
    args = parser.parse_args()

    if args.ui:
        launch_ui()
    elif args.input:
        converter = ApigeeToOpenAPI(args.input)
        base_path = converter.extract_zip()
        _ = converter.find_proxy_files(base_path)
        openapi_data = converter.convert_to_openapi()
        _, yaml_path = converter.save_to_file(openapi_data)
        if args.preview:
            preview_swagger_ui(yaml_path)
    else:
        parser.print_help()
