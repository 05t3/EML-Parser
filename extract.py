import email
import re
import sys
import base64
import hashlib
import argparse
import os
from email import policy

def parse_eml(file_path):
    """Parse the .eml file and extract relevant fields starting from Subject, including URLs from base64 HTML."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            msg = email.message_from_file(file, policy=policy.default)
    except UnicodeDecodeError:
        with open(file_path, 'r', encoding='latin-1') as file:
            msg = email.message_from_file(file, policy=policy.default)
    except Exception as e:
        print(f"Error reading .eml file {file_path}: {e}")
        return None

    # Extract headers starting from Subject
    subject = msg['Subject'] or 'None'
    from_addr = msg['From'] or 'None'
    to_addr = msg['To'] or 'None'
    cc = msg['Cc'] or 'None'
    in_reply_to = msg['In-Reply-To'] or 'None'
    date_str = msg['Date'] or 'None'
    message_id = msg['Message-ID'] or 'None'
    originating_ip = 'None'
    rdns = 'None'
    return_path = msg['Return-Path'] or 'None'

    # Clean Message-ID: extract content inside < > or use as-is if no brackets
    if message_id != 'None':
        message_id = message_id.strip()
        if message_id.startswith('<') and message_id.endswith('>'):
            message_id = message_id[1:-1].strip()

    # Extract email from To field
    to_email = 'None'
    if to_addr != 'None':
        email_match = re.search(r'<([^>]+)>|([\w\.-]+@[\w\.-]+)', to_addr)
        if email_match:
            to_email = email_match.group(1) or email_match.group(2)

    # Extract display name from From field
    display_name = 'None'
    if from_addr != 'None':
        name_match = re.search(r'^(.+?)(?:\s*<\S+>)?$', from_addr.strip())
        if name_match and name_match.group(1):
            if not re.match(r'^[\w\.-]+@[\w\.-]+$', name_match.group(1).strip()):
                display_name = name_match.group(1).strip() or 'None'

    # Extract email from From field
    from_email = 'None'
    if from_addr != 'None':
        email_match = re.search(r'<([^>]+)>|([\w\.-]+@[\w\.-]+)', from_addr)
        if email_match:
            from_email = email_match.group(1) or email_match.group(2)

    # Extract In-Reply-To content inside <>
    if in_reply_to != 'None':
        in_reply_to_match = re.search(r'<(.+?)>', in_reply_to)
        in_reply_to = in_reply_to_match.group(1) if in_reply_to_match else in_reply_to

    # Extract URLs from base64-encoded HTML parts recursively
    urls = set()
    def process_part(part):
        if part.is_multipart():
            for subpart in part.iter_parts():
                process_part(subpart)
        elif (part.get_content_type() == 'text/html' and 
              part.get('Content-Transfer-Encoding', '').lower() == 'base64'):
            try:
                encoded_content = part.get_payload()
                decoded_content = base64.b64decode(encoded_content).decode('utf-8', errors='ignore')
                url_pattern = r'https?://[^\s"\'<>]+'
                urls.update(re.findall(url_pattern, decoded_content))
            except Exception as e:
                print(f"Error decoding base64 content: {e}")
    if msg.is_multipart():
        for part in msg.iter_parts():
            process_part(part)
    urls = list(urls) if urls else 'None'

    # Extract Originating IP and rDNS from Received headers
    received_headers = msg.get_all('Received') or []
    if received_headers:
        # Use the first Received header for originating info
        first_header = received_headers[0].replace('\n', ' ').replace('\r', ' ')
        match = re.search(r'from\s+([^\s\[\]]+)\s+\([^\[\]]+\s\[([\d\.]+)\]\)', first_header, re.IGNORECASE)
        if match:
            rdns = match.group(1).strip()
            originating_ip = match.group(2).strip()

    # Extract SPF, DKIM, and DMARC
    spf_status = 'None'
    spf_ip = 'None'
    dkim_status = 'None'
    dkim_domain = 'None'
    dmarc_status = 'None'
    dmarc_action = 'None'

    auth_headers = msg.get_all('Authentication-Results') or []
    received_spf = msg.get('Received-SPF', '')
    for header in auth_headers:
        header_text = ' '.join(header.splitlines())
        spf_match = re.search(r'spf=([a-z]+)\s*\(sender IP is\s+([\d\.]+)\)', header_text, re.IGNORECASE)
        if spf_match and spf_status == 'None':
            spf_status = spf_match.group(1)
            spf_ip = spf_match.group(2)
        dkim_match = re.search(r'dkim=([a-z]+)\s*\(message not signed|.*signature\)', header_text, re.IGNORECASE)
        if dkim_match:
            dkim_status = dkim_match.group(1)
            domain_match = re.search(r'header\.d=([\w\.-]+)', header_text, re.IGNORECASE)
            dkim_domain = domain_match.group(1) if domain_match else 'None'
        dmarc_match = re.search(r'dmarc=([a-z]+)\s*action=([a-z]+)', header_text, re.IGNORECASE)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1)
            dmarc_action = dmarc_match.group(2)
        else:
            dmarc_match = re.search(r'dmarc=([a-z]+)', header_text, re.IGNORECASE)
            if dmarc_match and dmarc_status == 'None':
                dmarc_status = dmarc_match.group(1)
                dmarc_action = 'None'
    if received_spf and spf_status == 'None':
        spf_match = re.search(r'Received-Spf: (\w+)\s*\([^)]*domain of\s+[\w\.-]+\s+designates\s+([\d\.]+)\s+as permitted sender\)', received_spf, re.IGNORECASE)
        if spf_match:
            spf_status = spf_match.group(1)
            spf_ip = spf_match.group(2)

    # Clean Return-Path: remove < >
    if return_path != 'None' and return_path.startswith('<') and return_path.endswith('>'):
        return_path = return_path[1:-1]

    # Extract attachments with MD5 of content
    attachments = []
    if msg.is_multipart():
        for part in msg.iter_parts():
            if 'attachment' in part.get('Content-Disposition', ''):
                filename = part.get_filename() or 'None'
                if filename != 'None':
                    content = part.get_content()
                    if content:
                        try:
                            if isinstance(content, str):
                                decoded_content = base64.b64decode(content) if 'base64' in part.get('Content-Transfer-Encoding', '').lower() else content.encode('utf-8')
                            else:
                                decoded_content = content
                            md5_hash = hashlib.md5(decoded_content).hexdigest()
                        except Exception:
                            md5_hash = 'None'
                    else:
                        md5_hash = 'None'
                    attachments.append({
                        'Filename': filename,
                        'MD5 of Content': md5_hash
                    })

    # Format output (only from Subject onward)
    result = {
        'Subject': subject,
        'From': from_email,
        'Display Name': display_name,
        'To': to_email,
        'Cc': cc,
        'In-Reply-To': in_reply_to,
        'Date': date_str,
        'Message-ID': message_id,
        'Originating IP': originating_ip,
        'rDNS': rdns,
        'Return-Path': return_path,
        'SPF Status': spf_status,
        'SPF IP': spf_ip,
        'DKIM Status': dkim_status,
        'DKIM Domain': dkim_domain,
        'DMARC Status': dmarc_status,
        'DMARC Action': dmarc_action,
        'URLs': urls
    }
    if attachments:
        result['Attachment Details'] = attachments

    return result

def print_extracted_data(data, file_path):
    """Print the extracted data in a readable format starting from Subject with file context."""
    if not data:
        print(f"No data extracted from {file_path}.")
        return
    print(f"Results for {file_path}:")
    print("\n")
    for key, value in data.items():
        if key == 'Subject' or value != 'None':  # Print only from Subject and non-None values
            if key == 'URLs' and value != 'None' and isinstance(value, list):
                print("URLs:")
                for url in value:
                    print(f"  {url}")
            elif key == 'Attachment Details' and isinstance(value, list):
                print("Attachment Details:")
                for att in value:
                    for att_key, att_value in att.items():
                        print(f"  {att_key}: {att_value}")
            else:
                print(f"{key}: {value}")
    print("\n")
    print("========================================================================================================================================================================\n")

def main():
    parser = argparse.ArgumentParser(description="Parse .eml files and extract relevant information.")
    parser.add_argument('-i', '--input', type=str, help='Path to a single .eml file to parse')
    parser.add_argument('-d', '--directory', type=str, help='Path to a directory containing .eml files to parse')
    args = parser.parse_args()

    if not args.input and not args.directory:
        parser.print_help()
        sys.exit(1)

    if args.input:
        if not os.path.isfile(args.input) or not args.input.lower().endswith('.eml'):
            print(f"Error: {args.input} is not a valid .eml file.")
            sys.exit(1)
        extracted_data = parse_eml(args.input)
        print_extracted_data(extracted_data, args.input)

    if args.directory:
        if not os.path.isdir(args.directory):
            print(f"Error: {args.directory} is not a valid directory.")
            sys.exit(1)
        file_count = 0
        for root, _, files in os.walk(args.directory):
            for file in files:
                if file.lower().endswith('.eml'):
                    file_path = os.path.join(root, file)
                    extracted_data = parse_eml(file_path)
                    print_extracted_data(extracted_data, file_path)
                    file_count += 1
        if file_count > 0:
            print()  # Add a newline after the last delimiter for clean output

if __name__ == '__main__':
    main()