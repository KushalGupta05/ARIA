from pathlib import Path
import os
import json
import yaml
import argparse


def parse_sigma_for_rag(rules_directory, output_filepath):
    print(f"[*] Scanning directory for Sigma rules: {rules_directory}")

    if not os.path.exists(rules_directory):
        print(f"[!] Error: The directory {rules_directory} does not exist.")
        return

    # Automatically find ALL .yml files in all subfolders
    yaml_files = []
    for root, dirs, files in os.walk(rules_directory):
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                yaml_files.append(os.path.join(root, file))

    print(f"[*] Found {len(yaml_files)} YAML files. Parsing...")

    rag_documents = []
    success_count = 0
    error_count = 0

    for filepath in yaml_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                # Some files have multiple YAML documents separated by ---
                # We use safe_load_all to handle them safely
                docs = yaml.safe_load_all(f)

                for rule in docs:
                    if not rule or not isinstance(rule, dict):
                        continue

                    # Extract the critical fields
                    rule_id = rule.get('id', 'Unknown ID')
                    title = rule.get('title', 'Unknown Title')
                    description = rule.get('description', 'No description provided.')
                    status = rule.get('status', 'experimental')
                    level = rule.get('level', 'medium')

                    # Log Source (Where to find the logs)
                    logsource = rule.get('logsource', {})
                    product = logsource.get('product', 'Unknown Product')
                    category = logsource.get('category', 'Unknown Category')

                    # False Positives
                    false_positives = rule.get('falsepositives', [])
                    if isinstance(false_positives, str):
                        false_positives = [false_positives]

                    # Tags (This is where MITRE ATT&CK mapping lives! e.g., 'attack.t1059')
                    tags = rule.get('tags', [])
                    mitre_tags = [t for t in tags if t.startswith('attack.')]

                    # Format the Detection logic into a readable string
                    detection = rule.get('detection', {})
                    detection_str = json.dumps(detection, indent=2)

                    # Build the dense narrative for the LLM
                    content = f"Sigma Rule: {title}\n"
                    content += f"Severity Level: {level.upper()} | Status: {status}\n\n"
                    content += f"Description: {description}\n\n"

                    content += f"Log Source Required: Product = {product}, Category = {category}\n\n"

                    if mitre_tags:
                        content += f"Associated MITRE ATT&CK Tags: {', '.join(mitre_tags)}\n\n"

                    content += f"Detection Logic (YAML/JSON):\n{detection_str}\n\n"

                    if false_positives:
                        content += f"Known False Positives: {', '.join(false_positives)}\n"

                    # Add to our RAG list
                    rag_documents.append({
                        "metadata": {
                            "source": "SIGMA_RULES",
                            "doc_type": "detection_rule",
                            "sigma_id": rule_id,
                            "name": title,
                            "severity": level,
                            "product": product
                        },
                        "text_content": content.strip()
                    })
                    success_count += 1

        except Exception as e:
            # Skip unparseable files without crashing the whole script
            error_count += 1
            pass

    # Save to output JSON file
    print(f"[*] Successfully parsed {success_count} rules ({error_count} errors/skipped).")
    print(f"[*] Saving parsed documents to {output_filepath}")

    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print("[+] Sigma parsing complete! Data is ready for the Vector Database.")


if __name__ == "__main__":
    # Point this to the main "rules" folder you extracted
    default_input_dir = Path(__file__).resolve().parent / "sigma-master/rules"
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_sigma_data.json"

    parser = argparse.ArgumentParser(description="Parse Sigma YAML Rules for RAG SIEM")
    parser.add_argument("-d", "--dir", default=default_input_dir, help="Path to the main Sigma rules folder")
    parser.add_argument("-o", "--output", default=default_output, help="Path to output parsed JSON")

    args = parser.parse_args()

    parse_sigma_for_rag(args.dir, args.output)
