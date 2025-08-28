import sys
import csv
import json
import re

# --- PII Regex Patterns ---
# Using compiled regex for performance
PHONE_REGEX = re.compile(r'\b\d{10}\b')
AADHAAR_REGEX = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
PASSPORT_REGEX = re.compile(r'\b[A-Z]{1}\d{7}\b')
UPI_REGEX = re.compile(r'\b[\w.-]+@[\w.-]+\b') # A general pattern, refined in logic

# --- Combinatorial PII Keys ---
COMBINATORIAL_KEYS = {
    "email": "email",
    "address": "address",
    "device_id": "device_id",
    "ip_address": "ip_address"
}

# --- Redaction Functions ---

def mask_phone(phone_str):
    """Masks a 10-digit phone number, keeping the first 2 and last 2 digits."""
    return f"{phone_str[:2]}XXXXXX{phone_str[-2:]}"

def mask_aadhaar(aadhaar_str):
    """Masks a 12-digit Aadhaar number, keeping the first 4 and last 2 digits."""
    digits = aadhaar_str.replace(" ", "")
    return f"{digits[:4]} XXXX XX{digits[-2:]}"

def mask_passport(passport_str):
    """Masks a passport number, keeping the first 4 characters."""
    return f"{passport_str[:4]}XXXX"

def mask_upi(upi_str):
    """Masks a UPI ID's local part."""
    if '@' not in upi_str:
        return "[REDACTED_PII]"
    local_part, domain = upi_str.split('@', 1)
    if local_part.isdigit() and len(local_part) == 10:
        masked_local = mask_phone(local_part)
    else:
        masked_local = f"{local_part[:2]}XX"
    return f"{masked_local}@{domain}"

def mask_email(email_str):
    """Masks an email address's local part."""
    if '@' not in email_str:
        return "[REDACTED_PII]"
    local_part, domain = email_str.split('@', 1)
    masked_local = f"{local_part[:2]}XXX"
    return f"{masked_local}@{domain}"

def mask_name(first_name, last_name):
    """Masks a full name, keeping the first initial of each part."""
    masked_first = f"{first_name[0]}XXX" if first_name else ""
    masked_last = f"{last_name[0]}XXX" if last_name else ""
    return f"{masked_first} {masked_last}".strip()

# --- Main Processing Logic ---

def process_csv(input_file_path):
    """
    Reads a CSV, detects and redacts PII in a JSON column, and writes a new CSV.
    """
    output_file_path = input_file_path.replace('.csv', '_redacted.csv')
    total_records = 0
    pii_records = 0

    try:
        with open(input_file_path, mode='r', encoding='utf-8') as infile, \
             open(output_file_path, mode='w', newline='', encoding='utf-8') as outfile:

            reader = csv.reader(infile)
            writer = csv.writer(outfile)

            # Write header for the output file
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
            
            # Skip header from input file
            header = next(reader)
            try:
                id_index = header.index('record_id')
                json_index = header.index('data_json')
            except ValueError:
                print(f"Error: CSV must contain 'record_id' and 'data_json' columns.")
                return

            for row in reader:
                total_records += 1
                record_id = row[id_index]
                data_json_str = row[json_index]
                
                is_pii_found = False
                redacted_data = {}

                try:
                    data = json.loads(data_json_str)
                    redacted_data = data.copy() # Work on a copy
                    
                    # --- Step 1: Detect and Redact Standalone PII ---
                    standalone_pii_found = False
                    for key, value in data.items():
                        if not isinstance(value, str):
                            continue
                        
                        if key == "phone" and PHONE_REGEX.fullmatch(value):
                            redacted_data[key] = mask_phone(value)
                            standalone_pii_found = True
                        elif key == "aadhar" and AADHAAR_REGEX.fullmatch(value):
                            redacted_data[key] = mask_aadhaar(value)
                            standalone_pii_found = True
                        elif key == "passport" and PASSPORT_REGEX.fullmatch(value):
                            redacted_data[key] = mask_passport(value)
                            standalone_pii_found = True
                        elif key == "upi_id" and UPI_REGEX.fullmatch(value):
                            redacted_data[key] = mask_upi(value)
                            standalone_pii_found = True
                    
                    if standalone_pii_found:
                        is_pii_found = True

                    # --- Step 2: Detect Combinatorial PII ---
                    combinatorial_hits = []
                    # Check for full name
                    if 'first_name' in data and 'last_name' in data:
                        combinatorial_hits.append('name')
                    # Check for other keys
                    for key, field in COMBINATORIAL_KEYS.items():
                        if field in data:
                           combinatorial_hits.append(key)
                    
                    if len(combinatorial_hits) >= 2:
                        is_pii_found = True
                        # Redact all found combinatorial PII
                        if 'name' in combinatorial_hits:
                            first = data.get('first_name', '')
                            last = data.get('last_name', '')
                            redacted_data['name'] = mask_name(first, last)
                            # Clean up original name fields
                            if 'first_name' in redacted_data: del redacted_data['first_name']
                            if 'last_name' in redacted_data: del redacted_data['last_name']
                        
                        if 'email' in combinatorial_hits and 'email' in data:
                            redacted_data['email'] = mask_email(data['email'])
                        
                        if 'address' in combinatorial_hits:
                            redacted_data['address'] = "[REDACTED_ADDRESS]"
                        
                        if 'device_id' in combinatorial_hits:
                            redacted_data['device_id'] = "[REDACTED_PII]"

                        if 'ip_address' in combinatorial_hits:
                            redacted_data['ip_address'] = "[REDACTED_PII]"
                    
                    # --- Step 3: Finalize and Write Row ---
                    if is_pii_found:
                        pii_records += 1
                    
                    writer.writerow([record_id, json.dumps(redacted_data), is_pii_found])

                except json.JSONDecodeError as e:
                    # Handle malformed JSON as per requirements
                    print(f"Error parsing JSON for record {record_id}: {e}")
                    writer.writerow([record_id, data_json_str, False])

    except FileNotFoundError:
        print(f"Error: The file '{input_file_path}' was not found.")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return

    print(f"\nProcessing complete. Output written to: {output_file_path}")
    print(f"Processed {total_records} records")
    print(f"Records with PII: {pii_records}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_CANDIDATE_NAME.py <path_to_input_csv>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    process_csv(input_file)
