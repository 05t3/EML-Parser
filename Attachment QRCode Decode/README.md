# QR Code Decoder
This Python script decodes QR codes from images (PNG, JPG, JPEG) or PDF files. It supports processing a single file or all supported files in a directory, extracting QR code data such as URLs.

# Features

- Decode QR codes from individual image or PDF files using -i option.
- Process multiple files interactively in a directory using -d option.
- Command-line interface with help option (-h).
- Robust error handling and temporary file cleanup for PDF processing.

# Prerequisites

- Python: Version 3.6 or higher.
- System Dependencies (for Linux, e.g., Ubuntu):
- `libzbar0`: For QR code decoding.
- `libgl1-mesa-glx`: For OpenCV.
- `poppler-utils`: For PDF to image conversion.


## Python Libraries: Listed in requirements.txt.

### Installation

Install System Dependencies (Ubuntu/Debian example):

```bash
sudo apt-get update
sudo apt-get install libzbar0 libgl1-mesa-glx poppler-utils -y
```

Install Python Dependencies:

```bash
pip install -r requirements.txt
```


# Usage

Run the script with the following command-line options:

```
➜  python3 qr_code_decoder.py -h
usage: qr_code_decoder.py [-h] [-i INPUT] [-d DIRECTORY]

Decode QR codes from images or PDFs.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to a single image or PDF file
  -d DIRECTORY, --directory DIRECTORY
                        Path to a directory containing images or PDFs
```

## Examples

Process a single file:

```python
python3 qr_code_decoder.py -i "path/to/file.pdf"
```

Process all files in a directory:

```python
python3 qr_code_decoder.py -d "path/to/directory"
```

Show help:

```python
python3 qr_code_decoder.py -h
```


## Output

1. If a QR code is found, the script prints the decoded data (e.g., a URL).

```bash
➜  python3 qr_code_decoder.py -i Test.pdf
QR Code found in temp_qr_images/page_1.png: hxxps://example.site/#admin.corp@xyz.corp

Decoded QR Code Data: hxxps://example.site/#admin.corp@xyz.corp
```

2. If no QR code is found or an error occurs, an appropriate message is displayed.

```bash
➜  python3 qr_code_decoder.py -i Test-3.png

Processing PDFs/Test-3.png
No QR code found in temp_qr_images/page_1.png
```

3. For directory processing, each file's results are printed separately.


```bash
➜  python3 qr_code_decoder.py -d PDFs

Processing PDFs/Test.pdf
QR Code found in temp_qr_images/page_1.png: hxxps://example.site/#admin.corp@xyz.corp

Processing PDFs/Test-2.pdf
QR Code found in temp_qr_images/page_1.png: hxxps://example.site/#admin.corp@xyz.corp

➜  python3 qr_code_decoder.py -d PNGs

Processing PNGs/Test.png
No QR code found in PNGs/Test.png

Processing PNGs/Test-2.png
QR Code found in PNGs/Test-2.png: hxxps://example.site/#admin.corp@xyz.corp

Processing PNGs/Test-3.png
QR Code found in PNGsTest-3.png: hxxps://example.site/#admin.corp@xyz.corp
```

## Notes

- Ensure QR codes are clearly visible and not distorted in the input files.
- PDF processing converts pages to temporary images, which are automatically cleaned up.
- If you encounter issues (e.g., *missing libraries*), refer to the troubleshooting section below.

### Troubleshooting

> [!TIP]
> **Error: `libzbar.so` not found:Install libzbar0:**
> `sudo apt-get install libzbar0`


> [!TIP]
> **Reinstall `pyzbar` if needed:**
> `pip uninstall pyzbar`
> `pip install pyzbar`


> [!TIP]
> **Error: libGL.so.1 not found:**
> *Install `libgl1-mesa-glx`:*
> `sudo apt-get install libgl1-mesa-glx`


> [!TIP]
> **PDF conversion fails:**
> *Ensure `poppler-utils` is installed:*
> `sudo apt-get install poppler-utils`


> [!TIP]
> **Verify Python environment:**
> `python3 -m pip show pyzbar opencv-python pdf2image`



# License

**MIT License** - feel free to use and modify the code as needed.

# Contact

For issues or feature requests, please open an issue on the project repository or contact the maintainer.