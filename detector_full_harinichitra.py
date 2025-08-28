#!/usr/bin/env python3
"""
Real-time PII Defense - Project Guardian 2.0
PII Detector and Redactor for Flixkart Security Audit
"""

import csv
import json
import re
import sys
from typing import Dict, List, Tuple, Any


class PIIDetector:
    """
    A comprehensive PII detection and redaction system that identifies
    both standalone and combinatorial PII according to defined rules.
    """
    
    def __init__(self):
        # Regex patterns for standalone PII detection
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{4}\s*\d{4}\s*\d{4}\b|\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_pattern = re.compile(r'\b\w+@[a-zA-Z0-9]+\b|\b\d{10}@[a-zA-Z0-9]+\b')
        
        # Pattern for email detection
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        
        # Pattern for full names (first + last name)
        self.full_name_pattern = re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b')
        
        # Physical address indicators
        self.address_keywords = ['street', 'road', 'avenue', 'lane', 'block', 'sector', 'nagar', 'colony']
        
        # Combinatorial PII fields
        self.combinatorial_fields = {'name', 'email', 'address', 'device_id', 'ip_address'}
        
        # Standalone PII fields
        self.standalone_fields = {'phone', 'aadhar', 'passport', 'upi_id'}
    
    def is_phone_number(self, value: str) -> bool:
        """Check if value is a 10-digit phone number."""
        if not isinstance(value, str):
            value = str(value)
        return bool(self.phone_pattern.search(value.replace(' ', '').replace('-', '')))
    
    def is_aadhar_number(self, value: str) -> bool:
        """Check if value is a 12-digit Aadhar number."""
        if not isinstance(value, str):
            value = str(value)
        normalized = value.replace(' ', '').replace('-', '')
        return bool(self.aadhar_pattern.search(normalized)) and len(normalized) == 12
    
    def is_passport_number(self, value: str) -> bool:
        """Check if value is a passport number (P followed by 7 digits)."""
        if not isinstance(value, str):
            value = str(value)
        return bool(self.passport_pattern.search(value.upper()))
    
    def is_upi_id(self, value: str) -> bool:
        """Check if value is a UPI ID."""
        if not isinstance(value, str):
            value = str(value)
        return bool(self.upi_pattern.search(value))
    
    def is_email(self, value: str) -> bool:
        """Check if value is an email address."""
        if not isinstance(value, str):
            return False
        return bool(self.email_pattern.search(value))
    
    def is_full_name(self, value: str) -> bool:
        """Check if value contains both first and last name."""
        if not isinstance(value, str):
            return False
        # Check for full name pattern (First Last)
        return bool(self.full_name_pattern.search(value))
    
    def is_physical_address(self, value: str) -> bool:
        """Check if value appears to be a physical address."""
        if not isinstance(value, str):
            return False
        value_lower = value.lower()
        # Check for address keywords and numeric components (likely pin codes)
        has_keyword = any(keyword in value_lower for keyword in self.address_keywords)
        has_numbers = bool(re.search(r'\d+', value))
        return has_keyword and has_numbers and len(value) > 10
    
    def detect_standalone_pii(self, data: Dict[str, Any]) -> List[str]:
        """Detect standalone PII fields in the data."""
        pii_fields = []
        
        for key, value in data.items():
            if not value or value == '':
                continue
                
            value_str = str(value)
            
            # Check specific field names first
            if key in self.standalone_fields:
                if key == 'phone' and self.is_phone_number(value_str):
                    pii_fields.append(key)
                elif key == 'aadhar' and self.is_aadhar_number(value_str):
                    pii_fields.append(key)
                elif key == 'passport' and self.is_passport_number(value_str):
                    pii_fields.append(key)
                elif key == 'upi_id' and self.is_upi_id(value_str):
                    pii_fields.append(key)
            else:
                # Check by pattern regardless of field name
                if self.is_phone_number(value_str):
                    pii_fields.append(key)
                elif self.is_aadhar_number(value_str):
                    pii_fields.append(key)
                elif self.is_passport_number(value_str):
                    pii_fields.append(key)
                elif self.is_upi_id(value_str):
                    pii_fields.append(key)
        
        return pii_fields
    
    def detect_combinatorial_pii(self, data: Dict[str, Any]) -> Tuple[List[str], bool]:
        """Detect combinatorial PII and return fields + whether combination exists."""
        potential_pii = []
        
        for key, value in data.items():
            if not value or value == '':
                continue
                
            value_str = str(value)
            
            # Check for combinatorial PII fields
            if key in ['name', 'first_name', 'last_name'] and self.is_full_name(value_str):
                potential_pii.append(key)
            elif key == 'name':
                # Special handling for name field
                potential_pii.append(key)
            elif key == 'email' and self.is_email(value_str):
                potential_pii.append(key)
            elif key == 'address' and self.is_physical_address(value_str):
                potential_pii.append(key)
            elif key in ['device_id', 'ip_address'] and len(value_str) > 5:
                potential_pii.append(key)
        
        # Check if we have a valid combination (at least 2 combinatorial PII fields)
        has_combination = len(potential_pii) >= 2
        
        return potential_pii, has_combination
    
    def redact_value(self, value: str, field_name: str) -> str:
        """Redact PII values with appropriate masking."""
        if not isinstance(value, str):
            value = str(value)
        
        if self.is_phone_number(value):
            # Mask middle digits: 98XXXXXX10
            clean_phone = re.sub(r'[^\d]', '', value)
            if len(clean_phone) == 10:
                return f"{clean_phone[:2]}XXXXXX{clean_phone[-2:]}"
        
        elif self.is_aadhar_number(value):
            # Mask middle digits: 1234 XXXX XX12
            clean_aadhar = re.sub(r'[^\d]', '', value)
            if len(clean_aadhar) == 12:
                return f"{clean_aadhar[:4]} XXXX XX{clean_aadhar[-2:]}"
        
        elif self.is_passport_number(value):
            # Mask middle characters: P123XXXX
            if len(value) >= 4:
                return f"{value[:4]}XXXX"
        
        elif self.is_upi_id(value):
            # Mask username part: usXX@upi or 98XXXXXX10@ybl
            if '@' in value:
                username, domain = value.split('@', 1)
                if self.is_phone_number(username):
                    masked_username = f"{username[:2]}XXXXXX{username[-2:]}"
                else:
                    masked_username = f"{username[:2]}XX"
                return f"{masked_username}@{domain}"
        
        elif self.is_email(value):
            # Mask email: joXXX@gmail.com
            if '@' in value:
                username, domain = value.split('@', 1)
                if len(username) > 2:
                    masked_username = f"{username[:2]}XXX"
                else:
                    masked_username = "XXX"
                return f"{masked_username}@{domain}"
        
        elif self.is_full_name(value):
            # Mask name: JXXX SXXXX
            parts = value.split()
            masked_parts = []
            for part in parts:
                if len(part) > 1:
                    masked_parts.append(f"{part[0]}XXX")
                else:
                    masked_parts.append("XXX")
            return " ".join(masked_parts)
        
        elif field_name == 'address' or self.is_physical_address(value):
            # Replace with generic redaction
            return "[REDACTED_ADDRESS]"
        
        # Default redaction
        return "[REDACTED_PII]"
    
    def process_record(self, record_data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """Process a single record and return redacted data and PII flag."""
        redacted_data = record_data.copy()
        
        # Detect standalone PII
        standalone_pii = self.detect_standalone_pii(record_data)
        
        # Detect combinatorial PII
        combinatorial_fields, has_combination = self.detect_combinatorial_pii(record_data)
        
        # Determine if this record contains PII
        is_pii = len(standalone_pii) > 0 or has_combination
        
        # Redact standalone PII
        for field in standalone_pii:
            redacted_data[field] = self.redact_value(record_data[field], field)
        
        # Redact combinatorial PII if combination exists
        if has_combination:
            for field in combinatorial_fields:
                redacted_data[field] = self.redact_value(record_data[field], field)
        
        return redacted_data, is_pii


def main():
    """Main function to process CSV file."""
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = input_file.replace('.csv', '_redacted.csv')
    
    detector = PIIDetector()
    
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            csv_reader = csv.DictReader(infile)
            
            # Prepare output data
            output_rows = []
            
            for row in csv_reader:
                record_id = row['record_id']
                data_json = row['data_json']
                
                try:
                    # Parse JSON data
                    data = json.loads(data_json)
                    
                    # Process the record
                    redacted_data, is_pii = detector.process_record(data)
                    
                    # Prepare output row
                    output_row = {
                        'record_id': record_id,
                        'redacted_data_json': json.dumps(redacted_data),
                        'is_pii': is_pii
                    }
                    output_rows.append(output_row)
                    
                except json.JSONDecodeError as e:
                    print(f"Error parsing JSON for record {record_id}: {e}")
                    # Add row with original data and False flag
                    output_row = {
                        'record_id': record_id,
                        'redacted_data_json': data_json,
                        'is_pii': False
                    }
                    output_rows.append(output_row)
        
        # Write output CSV
        with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
            csv_writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            csv_writer.writeheader()
            csv_writer.writerows(output_rows)
        
        print(f"Processing complete. Output written to: {output_file}")
        print(f"Processed {len(output_rows)} records")
        pii_count = sum(1 for row in output_rows if row['is_pii'])
        print(f"Records with PII: {pii_count}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
