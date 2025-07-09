import re

def extract_fields(log_line):
    # Regular expression patterns for the required fields
    id_pattern = re.compile(r'\[id "\d+"\]')
    uri_pattern = re.compile(r'\[uri ".+?"\]')

    # Extracting the fields using the regular expression
    id_match = id_pattern.search(log_line)
    uri_match = uri_pattern.search(log_line)

    # Extract and return the matched text
    if id_match and uri_match:
        return id_match.group(), uri_match.group()
    return None, None

# Path to the log file
log_file_path = "/var/log/modsec_audit.log"

# Read the log file and process each line
with open(log_file_path, 'r', errors='ignore') as file:
    for line in file:
        if "Access denied with code 400" in line:  # Adjusted to match "Access denied with code 400"
            id_field, uri_field = extract_fields(line)
            if id_field and uri_field:
                print(f"{id_field} {uri_field}")
