from pathlib import Path
import os
import json
import argparse


def parse_nvd_for_rag(nvd_directory, output_filepath):
    print(f"[*] Scanning directory for CVEs: {nvd_directory}")

    if not os.path.exists(nvd_directory):
        print(f"[!] Error: The directory {nvd_directory} does not exist.")
        return

    # Automatically find ALL .json files in the 2024, 2025, 2026 folders
    json_files = []
    for root, dirs, files in os.walk(nvd_directory):
        for file in files:
            # Skip delta log files, only grab actual CVEs
            if file.endswith('.json') and not file.startswith('delta'):
                json_files.append(os.path.join(root, file))

    print(f"[*] Found {len(json_files)} CVE files. Parsing...")

    rag_documents = []
    success_count = 0
    error_count = 0

    for filepath in json_files:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)

            # Skip REJECTED CVEs to keep the database clean
            cve_metadata = cve_data.get('cveMetadata', {})
            if cve_metadata.get('state') == 'REJECTED':
                continue

            cve_id = cve_metadata.get('cveId', 'Unknown ID')
            containers = cve_data.get('containers', {})
            cna = containers.get('cna', {})

            # Extract Descriptions
            descriptions = cna.get('descriptions', [])
            eng_desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description provided.')

            # Extract Affected Products
            affected = cna.get('affected', [])
            products_list = []
            for item in affected:
                vendor = item.get('vendor', 'Unknown Vendor')
                product = item.get('product', 'Unknown Product')
                products_list.append(f"{vendor} {product}")

            # Extract Metrics (CVSS Scores)
            metrics = cna.get('metrics', [])
            cvss_score = "Unknown"
            cvss_severity = "Unknown"

            if metrics:
                # Try to grab CVSS 3.1 or 3.0 data
                cvss_data = metrics[0].get('cvssV3_1') or metrics[0].get('cvssV3_0') or {}
                cvss_score = cvss_data.get('baseScore', 'Unknown')
                cvss_severity = cvss_data.get('baseSeverity', 'Unknown')

            # Build the dense narrative for the LLM
            content = f"Vulnerability ID: {cve_id}\n"
            content += f"Base Score: {cvss_score} | Severity: {cvss_severity}\n\n"

            if products_list:
                content += f"Affected Products: {', '.join(products_list)}\n\n"

            content += f"Description: {eng_desc}\n"

            # Format into our standard JSON array!
            rag_documents.append({
                "metadata": {
                    "source": "NVD_CVE",
                    "doc_type": "vulnerability",
                    "cve_id": cve_id,
                    "severity": str(cvss_severity)
                },
                "text_content": content.strip()
            })
            success_count += 1

        except Exception as e:
            error_count += 1
            pass

    print(f"[*] Successfully parsed {success_count} recent CVEs ({error_count} errors/skipped).")

    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print(f"[+] Saved perfectly formatted JSON to {output_filepath}")


if __name__ == "__main__":
    default_input_dir = Path(__file__).resolve().parent / "."
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_recent_nvd_data.json"

    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", default=default_input_dir)
    parser.add_argument("-o", "--output", default=default_output)

    args = parser.parse_args()
    parse_nvd_for_rag(args.dir, args.output)
