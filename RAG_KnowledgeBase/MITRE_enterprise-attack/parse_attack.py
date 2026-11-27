from pathlib import Path
import json
import os
import argparse


def parse_mitre_attack_for_rag(input_filepath, output_filepath):
    print(f"[*] Loading STIX data from: {input_filepath}")

    if not os.path.exists(input_filepath):
        print(f"[!] Error: The file {input_filepath} does not exist.")
        return

    with open(input_filepath, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)

    objects = stix_data.get('objects', [])
    print(f"[*] Total raw STIX objects loaded: {len(objects)}")

    # 1. Dictionaries to hold our parsed, clean objects
    techniques = {}
    mitigations = {}
    groups = {}
    software = {}  # Includes Malware and Tools
    relationships = []

    print("[*] Categorizing objects and stripping boilerplate...")
    for obj in objects:
        obj_type = obj.get('type')
        obj_id = obj.get('id')

        # Parse Techniques (attack-pattern)
        if obj_type == 'attack-pattern':
            mitre_id = next((ext['external_id'] for ext in obj.get('external_references', []) if
                             ext['source_name'] == 'mitre-attack'), 'Unknown')

            # Skip deprecated or revoked techniques
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            techniques[obj_id] = {
                'id': obj_id,
                'mitre_id': mitre_id,
                'name': obj.get('name', 'Unknown Name'),
                'description': obj.get('description', 'No description provided.'),
                'tactics': [kill_chain['phase_name'] for kill_chain in obj.get('kill_chain_phases', [])],

                # Critical SIEM Context fields
                'detection': obj.get('x_mitre_detection', 'No detection guidance provided.'),
                'data_sources': obj.get('x_mitre_data_sources', []),
                'platforms': obj.get('x_mitre_platforms', []),

                # Placeholders for relationships we will resolve later
                'mitigations_list': [],
                'used_by_groups': [],
                'used_by_software': []
            }

        # Parse Mitigations (course-of-action)
        elif obj_type == 'course-of-action':
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            mitigations[obj_id] = obj.get('name', 'Unknown Mitigation')

        # Parse Threat Groups (intrusion-set)
        elif obj_type == 'intrusion-set':
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            groups[obj_id] = obj.get('name', 'Unknown Group')

        # Parse Software (malware and tool)
        elif obj_type in ['malware', 'tool']:
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue
            software[obj_id] = obj.get('name', 'Unknown Software')

        # Store relationships to resolve edges in the graph
        elif obj_type == 'relationship':
            relationships.append(obj)

    print(f"[*] Extracted {len(techniques)} Active Techniques.")
    print("[*] Resolving graph relationships (Uses, Mitigates)...")

    # 2. Resolve Relationships
    for rel in relationships:
        rel_type = rel.get('relationship_type')
        source_id = rel.get('source_ref')
        target_id = rel.get('target_ref')

        # A Mitigation mitigates a Technique
        if rel_type == 'mitigates' and source_id in mitigations and target_id in techniques:
            techniques[target_id]['mitigations_list'].append(mitigations[source_id])

        # A Threat Group uses a Technique
        if rel_type == 'uses' and source_id in groups and target_id in techniques:
            techniques[target_id]['used_by_groups'].append(groups[source_id])

        # Software (Malware/Tool) uses a Technique
        if rel_type == 'uses' and source_id in software and target_id in techniques:
            techniques[target_id]['used_by_software'].append(software[source_id])

    # 3. Format into LLM-friendly Documents
    print("[*] Formatting final documents for Vector DB...")
    rag_documents = []

    for tech_id, tech_data in techniques.items():
        # Build a dense, semantic narrative for the LLM
        content = f"Technique Name: {tech_data['name']} ({tech_data['mitre_id']})\n"

        if tech_data['tactics']:
            content += f"Tactics: {', '.join(tech_data['tactics'])}\n"
        if tech_data['platforms']:
            content += f"Platforms: {', '.join(tech_data['platforms'])}\n"

        content += f"\nDescription: {tech_data['description']}\n\n"
        content += f"Detection Guidance: {tech_data['detection']}\n"

        if tech_data['data_sources']:
            content += f"\nRequired Log Data Sources: {', '.join(tech_data['data_sources'])}\n"

        if tech_data['used_by_groups']:
            content += f"\nKnown Threat Groups utilizing this technique: {', '.join(tech_data['used_by_groups'])}\n"

        if tech_data['used_by_software']:
            content += f"\nKnown Malware/Tools utilizing this technique: {', '.join(tech_data['used_by_software'])}\n"

        if tech_data['mitigations_list']:
            content += f"\nMitigations: {', '.join(tech_data['mitigations_list'])}\n"

        # Structure the final document
        rag_documents.append({
            "metadata": {
                "source": "MITRE_ATTACK",
                "doc_type": "technique",
                "mitre_id": tech_data['mitre_id'],
                "name": tech_data['name']
            },
            "text_content": content.strip()
        })

    # 4. Save to output JSON file
    print(f"[*] Saving {len(rag_documents)} parsed documents to {output_filepath}")

    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)

    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print("[+] Parsing complete! Data is ready for the Vector Database.")


if __name__ == "__main__":
    default_input = Path(__file__).resolve().parent / "enterprise-attack.json"
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_mitre_data.json"

    parser = argparse.ArgumentParser(description="Parse MITRE ATT&CK STIX for RAG SIEM")
    parser.add_argument("-i", "--input", default=default_input, help="Path to enterprise-attack.json")
    parser.add_argument("-o", "--output", default=default_output, help="Path to output parsed JSON")

    args = parser.parse_args()

    parse_mitre_attack_for_rag(args.input, args.output)
