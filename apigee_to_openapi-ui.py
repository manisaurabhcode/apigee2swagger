#!/usr/bin/env python3
"""
Apigee Proxy → OpenAPI 3.0 Converter
------------------------------------
• Works from ZIP or extracted folder
• Generates openapi.yaml + openapi.json
• Optional Swagger UI preview (--preview)
• Optional simple upload UI (--ui)
"""

import os
import re
import json
import yaml
import zipfile
import tempfile
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Set
from flask import Flask, request, render_template_string, send_file


# =====================================================
#   Core Converter
# =====================================================
class ApigeeToOpenAPI:
    def __init__(self, proxy_source: str):
        self.src_path = Path(proxy_source)
        self.temp_dir = None
        self.openapi: Dict[str, Any] = {}

    # ---------- Helpers ----------
    def _load_xml(self, path: Path) -> Optional[ET.Element]:
        try:
            return ET.parse(path).getroot()
        except Exception:
            return None

    def _text(self, e: Optional[ET.Element], default=""):
        return e.text.strip() if e is not None and e.text else default

    def _attr(self, e: Optional[ET.Element], key, default=""):
        return e.get(key, default) if e is not None else default

    # ---------- I/O ----------
    def extract_zip(self) -> Path:
        """If input is ZIP, extract it."""
        if zipfile.is_zipfile(self.src_path):
            self.temp_dir = Path(tempfile.mkdtemp())
            with zipfile.ZipFile(self.src_path, "r") as z:
                z.extractall(self.temp_dir)
            print(f"📦 Extracted to {self.temp_dir}")
            return self.temp_dir
        elif self.src_path.is_dir():
            return self.src_path
        raise ValueError("Input must be a zip or directory")

    # ---------- Main ----------
    def generate(self, api_name: Optional[str] = None, endpoint_url: str = "") -> Dict[str, Any]:
        base = self.extract_zip()
        apiproxy = base / "apiproxy"
        if not apiproxy.exists():
            raise FileNotFoundError("apiproxy folder not found inside bundle")
    
        # Auto-detect proxy XML file if name not provided or mismatched
        xml_files = list(apiproxy.glob("*.xml"))
        if not xml_files:
            raise FileNotFoundError("No API proxy XML found in apiproxy/")
        api_xml = xml_files[0]
        if not api_name:
            api_name = api_xml.stem
    
        root = self._load_xml(api_xml)
        if root is None:
            raise FileNotFoundError(f"Cannot parse {api_xml}")


        # Init base spec
        parsed_url = urlparse(endpoint_url)
        self.openapi = {
            "openapi": "3.0.3",
            "info": {
                "title": self._text(root.find("DisplayName"), api_name),
                "description": self._text(root.find("Description")),
                "version": f"{root.get('revision','1')}.0.0",
            },
            "servers": [{"url": f"{parsed_url.scheme}://{parsed_url.netloc}"}] if endpoint_url else [],
            "paths": {},
            "components": {"securitySchemes": {}},
            "tags": [],
        }

        # ---- proxy endpoints
        proxies = (apiproxy / "proxies").glob("*.xml")
        for pxml in proxies:
            p_root = self._load_xml(pxml)
            if not p_root:
                continue
            self._parse_proxy_endpoint(p_root)

        # ---- targets
        targets = (apiproxy / "targets").glob("*.xml")
        backends = []
        for txml in targets:
            t_root = self._load_xml(txml)
            if not t_root:
                continue
            u = t_root.find(".//HTTPTargetConnection/URL")
            if u is not None:
                backends.append({"name": txml.stem, "url": self._text(u)})
        if backends:
            self.openapi["info"]["x-backend-services"] = backends

        return self.openapi

    # ---------- proxy parsing ----------
    def _parse_proxy_endpoint(self, root: ET.Element):
        base_path = self._text(root.find(".//HTTPProxyConnection/BasePath"))
        flows = root.findall(".//Flows/Flow")
        for flow in flows:
            cond = self._text(flow.find("Condition"))
            verb, path = self._extract_path_verb(cond)
            if not path:
                continue
            if not path.startswith("/"):
                path = f"{base_path or ''}/{path}".replace("//", "/")

            op = {
                "operationId": flow.get("name", ""),
                "responses": {"200": {"description": "OK"}},
            }
            tag = path.strip("/").split("/")[0] or "default"
            op["tags"] = [tag]
            if tag not in [t["name"] for t in self.openapi["tags"]]:
                self.openapi["tags"].append({"name": tag})
            if path not in self.openapi["paths"]:
                self.openapi["paths"][path] = {}
            self.openapi["paths"][path][verb or "get"] = op

    def _extract_path_verb(self, condition: str):
        v = re.search(r'request\.(verb|method)\s*[=!]+\s*"([^"]+)"', condition)
        p = re.search(r'proxy\.pathsuffix\s+(MatchesPath|=|~)\s*"([^"]+)"', condition)
        return (v.group(2).lower() if v else "get", p.group(2) if p else "")

    # ---------- save ----------
    def save(self, out_name="openapi") -> (Path, Path):
        j = Path(f"{out_name}.json")
        y = Path(f"{out_name}.yaml")
        with open(j, "w", encoding="utf8") as jf:
            json.dump(self.openapi, jf, indent=2)
        with open(y, "w", encoding="utf8") as yf:
            yaml.dump(self.openapi, yf, sort_keys=False)
        print(f"✅ Saved {j} and {y}")
        return j, y


# =====================================================
#   Swagger Preview
# =====================================================
def swagger_preview(spec_path: Path, port=5001):
    app = Flask(__name__)

    @app.route("/")
    def ui():
        return f"""
        <!DOCTYPE html><html><head>
        <title>Swagger UI</title>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
        </head><body><div id="swagger"></div>
        <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
        <script>
        SwaggerUIBundle({{
          url: '/spec',
          dom_id: '#swagger'
        }});
        </script></body></html>"""

    @app.route("/spec")
    def spec():
        return send_file(spec_path)

    webbrowser.open(f"http://127.0.0.1:{port}")
    app.run(port=port, debug=False)


# =====================================================
#   Simple Upload UI
# =====================================================
def launch_ui():
    app = Flask(__name__)
    workdir = Path(tempfile.mkdtemp())

    HTML = """
    {% raw %}
    <!DOCTYPE html><html><head>
      <meta charset="utf-8"><title>Apigee → OpenAPI</title>
      <style>body{font-family:sans-serif;margin:40px;}
      .box{border:2px dashed #aaa;padding:20px;border-radius:10px;width:420px;}
      </style></head><body>
      <h2>Apigee Proxy → OpenAPI 3.0</h2>
      <form method="post" enctype="multipart/form-data" class="box">
        <input type="file" name="file" accept=".zip" required><br><br>
        <input type="text" name="endpoint" placeholder="Proxy endpoint URL (optional)" style="width:400px"><br><br>
        <button type="submit">Convert</button>
      </form>
    {% endraw %}
    {% if swagger_url %}
      <p>✅ Conversion done.</p>
      <a href="{{ swagger_url }}" target="_blank">Open Swagger UI Preview</a>
    {% endif %}
    {% raw %}</body></html>{% endraw %}
    """

    @app.route("/", methods=["GET"])
    def index():
        return render_template_string(HTML, swagger_url=None)

    @app.route("/", methods=["POST"])
    def convert():
        f = request.files["file"]
        endpoint = request.form.get("endpoint", "")
        z = workdir / f.filename
        f.save(z)
        conv = ApigeeToOpenAPI(z)
        data = conv.generate(endpoint_url=endpoint)
        _, y = conv.save(workdir / "openapi")
        return render_template_string(HTML, swagger_url=f"/swagger/{y.name}")

    @app.route("/swagger/<fname>")
    def swagger(fname):
        return f"""
        <!DOCTYPE html><html><head>
        <meta charset="utf-8"><title>Swagger UI</title>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css">
        </head><body><div id="swagger"></div>
        <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
        <script>SwaggerUIBundle({{url:'/files/{fname}',dom_id:'#swagger'}});</script>
        </body></html>"""

    @app.route("/files/<fname>")
    def files(fname):
        return send_file(workdir / fname)

    print("🌐 UI at http://127.0.0.1:5000")
    webbrowser.open("http://127.0.0.1:5000")
    app.run(port=5000, debug=False)


# =====================================================
#   CLI Entry
# =====================================================
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Convert Apigee proxy bundles to OpenAPI 3.0")
    p.add_argument("input", nargs="?", help="ZIP or folder path")
    p.add_argument("--preview", action="store_true", help="Launch Swagger UI after conversion")
    p.add_argument("--ui", action="store_true", help="Launch simple upload UI")
    p.add_argument("--endpoint", default="", help="Base proxy endpoint URL")
    args = p.parse_args()

    if args.ui:
        launch_ui()
    elif args.input:
        conv = ApigeeToOpenAPI(args.input)
        spec = conv.generate(endpoint_url=args.endpoint)
        _, y = conv.save()
        if args.preview:
            swagger_preview(y)
    else:
        p.print_help()
