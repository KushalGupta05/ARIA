from pathlib import Path
import os
import json
import argparse


def parse_kev_for_rag(input_filepath, output_filepath):
    print(f"[*] Loading CISA KEV data from: {input_filepath}")

    if not os.path.exists(input_filepath):
        print(f"[!] Error: The file {input_filepath} does not exist.")
        return

    # Load the raw CISA JSON
    with open(input_filepath, 'r', encoding='utf-8') as f:
        kev_data = json.load(f)

    vulnerabilities = kev_data.get('vulnerabilities', [])
    print(f"[*] Found {len(vulnerabilities)} Known Exploited Vulnerabilities.")

    rag_documents = []

    for vuln in vulnerabilities:
        cve_id = vuln.get('cveID', 'Unknown CVE')
        vendor = vuln.get('vendorProject', 'Unknown Vendor')
        product = vuln.get('product', 'Unknown Product')
        name = vuln.get('vulnerabilityName', 'Unknown Name')
        description = vuln.get('shortDescription', 'No description provided.')
        action = vuln.get('requiredAction', 'No action provided.')
        date_added = vuln.get('dateAdded', 'Unknown Date')

        # Build a dense, semantic narrative for the LLM
        content = f"Vulnerability: {name} ({cve_id})\n"
        content += f"Vendor/Project: {vendor}\n"
        content += f"Affected Product: {product}\n\n"

        content += f"Description: {description}\n\n"

        content += f"Required Remediation Action: {action}\n"
        content += f"Added to CISA KEV Catalog on: {date_added}\n"

        # Format into our standard JSON array for the Vector DB
        rag_documents.append({
            "metadata": {
                "source": "CISA_KEV",
                "doc_type": "vulnerability",
                "cve_id": cve_id,
                "vendor": vendor,
                "product": product
            },
            "text_content": content.strip()
        })

    # Save to output JSON file
    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print(f"[+] Successfully saved {len(rag_documents)} parsed KEV documents to {output_filepath}")


if __name__ == "__main__":
    # Point this to where you saved the CISA JSON file
    default_input = Path(__file__).resolve().parent / "known_exploited_vulnerabilities.json"
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_cisa_kev_data.json"

    parser = argparse.ArgumentParser(description="Parse CISA KEV for RAG SIEM")
    parser.add_argument("-i", "--input", default=default_input, help="Path to known_exploited_vulnerabilities.json")
    parser.add_argument("-o", "--output", default=default_output, help="Path to output parsed JSON")

    args = parser.parse_args()

    parse_kev_for_rag(args.input, args.output)
