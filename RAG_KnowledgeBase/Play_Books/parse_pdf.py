from pathlib import Path
import os
import json
import argparse
import PyPDF2


def parse_pdfs_for_rag(pdf_directory, output_filepath):
    print(f"[*] Scanning for PDFs in: {pdf_directory}")

    if not os.path.exists(pdf_directory):
        print(f"[!] Error: Directory not found.")
        return

    rag_documents = []
    success_count = 0

    for root, dirs, files in os.walk(pdf_directory):
        for filename in files:
            if filename.endswith(".pdf"):
                filepath = os.path.join(root, filename)

            try:
                # Open and extract text from the PDF
                with open(filepath, 'rb') as file:
                    reader = PyPDF2.PdfReader(file)
                    text_content = ""

                    for page in reader.pages:
                        extracted = page.extract_text()
                        if extracted:
                            text_content += extracted + "\n"

                # Clean up the text a bit
                text_content = text_content.strip()

                if text_content:
                    # Format into our standard JSON array
                    rag_documents.append({
                        "metadata": {
                            "source": "IR_PLAYBOOKS",
                            "doc_type": "playbook",
                            "name": filename.replace('.pdf', '')
                        },
                        "text_content": text_content
                    })
                    success_count += 1
                    print(f"[+] Parsed: {filename}")

            except Exception as e:
                print(f"[!] Failed to parse {filename}: {e}")

    # Save to output JSON file
    os.makedirs(os.path.dirname(os.path.abspath(output_filepath)), exist_ok=True)
    Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(rag_documents, f, indent=4)

    print(f"\n[*] Successfully parsed {success_count} playbooks!")
    print(f"[*] Saved to: {output_filepath}")


if __name__ == "__main__":
    default_input = Path(__file__).resolve().parent / "IRM-main/EN"
    default_output = Path(__file__).resolve().parents[2] / "ML_Model" / "RAG_Pipeline" / "data" / "raw" / "parsed_playbooks_data.json"

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", default=default_input)
    parser.add_argument("-o", "--output", default=default_output)

    args = parser.parse_args()
    parse_pdfs_for_rag(args.input, args.output)
