# EML-Parser Tool

## Overview
The EML-Parser Tool is a Python-based utility designed to parse .eml email files and extract key information such as headers, URLs, authentication details, and attachment metadata. It supports nested multipart structures and base64-encoded content, making it ideal for analyzing email data efficiently.

## Features

- Extracts email headers (Subject, From, To, Cc, etc.).
- Identifies URLs from base64-encoded HTML parts.
- Parses authentication details (SPF, DKIM, DMARC).
- Computes MD5 hashes for attachment content.
- Handles multi-line and nested email structures.

## Requirements

- Python 3.x
- No external dependencies beyond the Python standard library

## Installation

1. Clone the repository or download the extract.py script:

```bash
git clone https://github.com/05t3/EML-Parser.git
cd EML-Parser
```

### Help

Display available options:

```bash
➜  python3 extract.py -h                        
Parse .eml files and extract relevant information.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to a single .eml file to parse
  -d DIRECTORY, --directory DIRECTORY
                        Path to a directory containing .eml files to parse
  -o OUTPUT, --output OUTPUT
                        Output file path (e.g., output.json)
  --format {text,json,csv}
                        Output format (text, json, csv)
```

### Usage

Run the script with the following command-line options:

#### Parse a Single .eml File

```bash
python3 extract.py -i path/to/your/example.eml
```

#### Parse All .eml Files in a Directory

```bash
python3 extract.py -d path/to/directory
```

#### Saving Output

The tool allows you to save output in various formats like text, CSV, and JSON. For example, to extract fields from several .eml files in a specific directory, run:

```bash
➜  python3 extract.py -d path/to/directory --format csv -o output.csv
Data exported to output.csv in CSV format.
➜  python3 extract.py -d path/to/directory --format json -o output.json
Data exported to output.json in JSON format.
➜  python3 extract.py -d path/to/directory --format text -o output.txt
Data exported to output.txt in TEXT format.
```

If you also want to print output on the terminal with a specific format, e.g., JSON, simply run:

```bash
➜  python3 extract.py -d path/to/directory --format json

[
  {
    "Subject": "Meeting Invitation",
    "From": "user@dummy.com",
    "Display Name": "Dummy User",
    "To": "recipient@dummy.com",
    "Cc": "None",
    "In-Reply-To": "None",
    "Date": "Mon, 23 Jun 2025 12:00:00 +0000",
    "Message-ID": "<123456789@dummy.com>",
    "Originating IP": "192.168.1.1",
    "rDNS": "mail.dummy.com",
    "Return-Path": "sender@dummy.com",
    "SPF Status": "pass",
    "SPF IP": "192.168.1.1",
    "DKIM Status": "pass",
    "DKIM Domain": "dummy.com",
    "DMARC Status": "pass",
    "DMARC Action": "none",
    "URLs": [
      "https://example.com/link1",
      "https://example.com/link2"
    ],
    "EML File Md5sum": "d41d8cd98f00b204e9800998ecf8427e"
  }
]
```

Sample Text Output

```bash
➜  python3 extract.py -d path/to/directory --format text

Results for example.eml:

EML File Md5sum: d41d8cd98f00b204e9800998ecf8427e
Subject: Example Subject Line
From: example.email@domain.com
Display Name: Example Name
To: recipient@domain.com
Cc: None
In-Reply-To: None
Date: Mon, 23 Jun 2025 12:00:00 +0000
Message-ID: <123456789@domain.com>
Originating IP: 192.168.1.1
rDNS: mail.example.com
Return-Path: sender@domain.com
SPF Status: pass
SPF IP: 192.168.1.1
DKIM Status: pass
DKIM Domain: domain.com
DMARC Status: pass
DMARC Action: none
Attachment Details:
  Filename: document.pdf
  MD5 of Content: d41d8cd98f00b204e9800998ecf8427e
URLs:
  https://example.com/link1
  https://example.com/link2


```

## Future Adjustments

The following features are planned for future development but are not yet implemented:

- [ ] **VirusTotal Integration**: Lookup MD5 sums of attached files to check for malware.
- [ ] **API Integration**: Assess the maliciousness of detected URLs.
- [ ] **AI Integration**: Detect malicious emails/phishing emails and categorize them (e.g., spam, credential harvesters).
- [x] **Export Capability**: Support output in common formats such as JSON, YAML, or CSV to enable ingestion in various tools.
- [ ] **URL Redirect Tracking**: Follow through detected URLs and display the entire redirect trail.
- [ ] **Email Thread Reconstruction**: Aggregate related emails using In-Reply-To and Message-ID to build conversation threads.
- [ ] **Attachment Extraction**: Save attachments to disk with their original filenames for further analysis.
- [ ] **Rate Limiting for APIs:** Implement rate limiting and caching for future API calls to avoid usage limits.
- [ ] **Email Header Validation**: Validate header integrity against email standards for compliance checks.
- [ ] **Refine SPF,DMARC,DKIM Checks**


## Contributing

Feel free to submit issues or pull requests on the GitHub repository. Contributions to improve functionality or add features are welcome!

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contact

For support or questions, reach out via [mail](05t3@protonmail.com) or open an issue on the repository.