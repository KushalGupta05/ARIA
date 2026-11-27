from pathlib import Path
import json
import os
import argparse


def parse_capec_for_rag(input_filepath, output_filepath):
    print(f"[*] Loading CAPEC STIX data from: {input_filepath}")

    if not os.path.exists(input_filepath):
        print(f"[!] Error: The file {input_filepath} does not exist.")
        return

    with open(input_filepath, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)

    objects = stix_data.get('objects', [])
    print(f"[*] Total raw STIX objects loaded: {len(objects)}")

    capec_patterns = {}
    mitigations = {}
    relationships = []

    for obj in objects:
        obj_type = obj.get('type')
        obj_id = obj.get('id')

        if obj_type == 'attack-pattern':
            # CHANGE 1: Look for "capec" instead of "mitre-attack"
            capec_id = next(
                (ext['external_id'] for ext in obj.get('external_references', []) if ext['source_name'] == 'capec'),
                'Unknown')

            if obj.get('revoked') or obj.get('x_capec_status') == 'Deprecated':
                continue

            capec_patterns[obj_id] = {
                'id': obj_id,
                'capec_id': capec_id,
                'name': obj.get('name', 'Unknown Name'),
                'description': obj.get('description', 'No description provided.'),

                # CHANGE 2: Extract CAPEC-specific fields
                'likelihood': obj.get('x_capec_likelihood_of_attack', 'Unknown'),
                'severity': obj.get('x_capec_typical_severity', 'Unknown'),
                'prerequisites': obj.get('x_capec_prerequisites', []),
                'skills': obj.get('x_capec_skills_required', {}),

                'mitigations_list': []
            }

        elif obj_type == 'course-of-action':
            mitigations[obj_id] = obj.get('name', obj.get('description', 'Unknown Mitigation'))

        elif obj_type == 'relationship':
            relationships.append(obj)

    print("[*] Resolving graph relationships (Mitigates)...")
    for rel in relationships:
        if rel.get('relationship_type') == 'mitigates':
            source_id = rel.get('source_ref')
            target_id = rel.get('target_ref')
            if source_id in mitigations and target_id in capec_patterns:
                capec_patterns[target_id]['mitigations_list'].append(mitigations[source_id])

    print("[*] Formatting final documents for Vector DB...")
    rag_documents = []

    for c_id, c_data in capec_patterns.items():
        # CHANGE 3: Build the narrative with the new CAPEC fields
        content = f"CAPEC Pattern: {c_data['name']} ({c_data['capec_id']})\n"
        content += f"Likelihood of Attack: {c_data['likelihood']}\n"
        content += f"Typical Severity: {c_data['severity']}\n\n"
        content += f"Description: {c_data['description']}\n\n"

        if c_data['prerequisites']:
            content += f"Prerequisites for Attack: {', '.join(c_data['prerequisites'])}\n\n"

        if c_data['mitigations_list']:
            content += f"Mitigations: {', '.join(c_data['mitigations_list'])}\n"

        rag_documents.append({
            "metadata": {
                "source": "MITRE_CAPEC",
                "doc_type": "attack_pattern",
                "capec_id": c_data['capec_id'],
                "name": c_data['name']
            },
            "text_content": content.strip()
        })

    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print(f"[+] Saved {len(rag_documents)} CAPEC documents to {output_filepath}")


if __name__ == "__main__":
    default_input = Path(__file__).resolve().parent / "stix-capec.json"
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_capec_data.json"

    parser = argparse.ArgumentParser(description="Parse MITRE CAPEC STIX for RAG SIEM")
    parser.add_argument("-i", "--input", default=default_input, help="Path to stix-capec.json")
    parser.add_argument("-o", "--output", default=default_output, help="Path to output parsed JSON")

    args = parser.parse_args()
    parse_capec_for_rag(args.input, args.output)
