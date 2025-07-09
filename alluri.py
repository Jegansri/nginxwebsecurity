import re

# Path to the log file
log_file_path = '/var/log/modsec_audit.log'

# Function to extract all URIs from a given log file
def extract_uris_from_log(file_path):
    try:
        uris = []
        with open(file_path, 'r', errors='ignore') as file:
            log_entry = []
            for line in file:
                if line.strip() == "":
                    # End of log entry, process it
                    entry = '\n'.join(log_entry)
                    uri_match = re.search(r'\[uri "(.*?)"\]', entry)
                    if uri_match:
                        uris.append(uri_match.group(1))
                    log_entry = []  # Reset for next log entry
                else:
                    log_entry.append(line)
            # Process the last log entry if the file does not end with a blank line
            if log_entry:
                entry = '\n'.join(log_entry)
                uri_match = re.search(r'\[uri "(.*?)"\]', entry)
                if uri_match:
                    uris.append(uri_match.group(1))

        return uris
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# Extract the URIs
extracted_uris = extract_uris_from_log(log_file_path)

# Print all extracted URIs
for uri in extracted_uris:
    print(uri)
