import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict

# ==============================
# CONFIG
# ==============================
APIGEE_BUNDLE_PATH = "apigee_bundle/apiproxy"
OUTPUT_JSON = "apigee_policies_full.json"

# ==============================
# UTILITIES
# ==============================

def parse_xml_file(file_path):
    """Safely parse XML file and return root element."""
    try:
        tree = ET.parse(file_path)
        return tree.getroot()
    except Exception as e:
        print(f"⚠️ Error parsing {file_path}: {e}")
        return None


def get_text(element, tag_name):
    """Return text content for a given tag."""
    if element is None:
        return ""
    tag = element.find(tag_name)
    return tag.text.strip() if tag is not None and tag.text else ""


def extract_policy_references(flow_root):
    """
    Extract references to policies within ProxyEndpoint and TargetEndpoint.
    Returns mapping of {policy_name: flow_name or flow_type}
    """
    policy_references = {}

    for flow_type in ["PreFlow", "PostFlow"]:
        node = flow_root.find(flow_type)
        if node is not None:
            for step in node.findall(".//Step"):
                policy_name = get_text(step, "Name")
                if policy_name:
                    policy_references[policy_name] = flow_type

    # Custom Flows
    for flow in flow_root.findall("Flows/Flow"):
        flow_name = flow.attrib.get("name", "UnnamedFlow")
        for step in flow.findall(".//Step"):
            policy_name = get_text(step, "Name")
            if policy_name:
                policy_references[policy_name] = flow_name

    return policy_references


# ==============================
# POLICY EXTRACTION
# ==============================

def parse_policy_xml(policy_path):
    """Parse a policy XML and return normalized info."""
    root = parse_xml_file(policy_path)
    if root is None:
        return None

    policy_name = root.attrib.get("name", os.path.basename(policy_path).replace(".xml", ""))
    policy_type = root.tag
    display_name = get_text(root, "DisplayName")
    condition = get_text(root, "Condition")

    # Collect attributes (flat dictionary)
    attributes = {}
    for elem in root.iter():
        if elem is root:
            continue  # Skip root
        tag = elem.tag
        text = elem.text.strip() if elem.text else ""
        if text:
            key = f"{root.tag}.{tag}" if tag not in attributes else f"{tag}_dup"
            attributes[key] = text
        # Also collect attributes from XML attributes (e.g., enabled="true")
        for k, v in elem.attrib.items():
            attributes[f"{tag}.{k}"] = v

    with open(policy_path, "r", encoding="utf-8") as f:
        xml_content = f.read()

    return {
        "name": policy_name,
        "type": policy_type,
        "displayName": display_name,
        "condition": condition,
        "attributes": attributes,
        "xmlSource": xml_content
    }


def extract_policy_flow_mappings(apigee_path):
    """Find where each policy is used (PreFlow, PostFlow, custom flow)."""
    flow_mappings = defaultdict(lambda: "Unmapped")

    proxy_dir = os.path.join(apigee_path, "proxies")
    target_dir = os.path.join(apigee_path, "targets")

    for folder in [proxy_dir, target_dir]:
        if not os.path.exists(folder):
            continue
        for fname in os.listdir(folder):
            if not fname.endswith(".xml"):
                continue
            root = parse_xml_file(os.path.join(folder, fname))
            if root is None:
                continue
            refs = extract_policy_references(root)
            for name, flow in refs.items():
                flow_mappings[name] = flow

    return flow_mappings


# ==============================
# MAIN EXTRACTION
# ==============================

def extract_apigee_policies(bundle_path):
    """Extracts all policies and relevant metadata."""
    policies_dir = os.path.join(bundle_path, "policies")
    if not os.path.exists(policies_dir):
        raise FileNotFoundError(f"No 'policies' folder found at {policies_dir}")

    flow_mappings = extract_policy_flow_mappings(bundle_path)
    policies = []

    for filename in os.listdir(policies_dir):
        if not filename.endswith(".xml"):
            continue
        policy_path = os.path.join(policies_dir, filename)
        policy_data = parse_policy_xml(policy_path)
        if policy_data:
            flow = flow_mappings.get(policy_data["name"], "Unmapped")
            policy_data["flow"] = flow
            policies.append(policy_data)

    return policies


# ==============================
# MAIN EXECUTION
# ==============================

def main():
    print("🔍 Scanning Apigee bundle for policies...")

    apiproxy_xml_path = os.path.join(APIGEE_BUNDLE_PATH, "apiproxy.xml")
    api_name = "UnknownAPI"
    if os.path.exists(apiproxy_xml_path):
        root = parse_xml_file(apiproxy_xml_path)
        if root is not None:
            api_name = root.attrib.get("name", "UnnamedAPI")

    policies = extract_apigee_policies(APIGEE_BUNDLE_PATH)

    output = {
        "api_name": api_name,
        "policy_count": len(policies),
        "policies": policies
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    print(f"✅ Export complete — {len(policies)} policies extracted")
    print(f"📁 Output: {OUTPUT_JSON}")


if __name__ == "__main__":
    main()