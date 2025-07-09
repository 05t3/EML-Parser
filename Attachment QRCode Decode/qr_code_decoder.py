import cv2
import numpy as np
from pyzbar.pyzbar import decode
from pdf2image import convert_from_path
import os
from pathlib import Path
import argparse

def decode_qr_from_image(image_path):
    """Decode QR code from an image file."""
    try:
        # Read the image using OpenCV
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError(f"Could not load image: {image_path}")

        # Convert to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Decode QR code
        qr_codes = decode(gray)
        if not qr_codes:
            print(f"No QR code found in {image_path}")
            return None

        # Extract and return the first QR code's data
        qr_data = qr_codes[0].data.decode('utf-8')
        print(f"QR Code found in {image_path}: {qr_data}")
        return qr_data

    except Exception as e:
        print(f"Error processing image {image_path}: {str(e)}")
        return None

def decode_qr_from_pdf(pdf_path):
    """Decode QR code from a PDF file by converting pages to images."""
    try:
        # Convert PDF to images
        images = convert_from_path(pdf_path)
        temp_dir = Path("temp_qr_images")
        temp_dir.mkdir(exist_ok=True)

        qr_data = None
        for i, image in enumerate(images):
            # Save temporary image
            temp_image_path = temp_dir / f"page_{i+1}.png"
            image.save(temp_image_path, "PNG")

            # Decode QR code from the image
            result = decode_qr_from_image(str(temp_image_path))
            if result:
                qr_data = result
                break

        # Clean up temporary images
        for temp_file in temp_dir.glob("*.png"):
            temp_file.unlink()
        temp_dir.rmdir()

        return qr_data

    except Exception as e:
        print(f"Error processing PDF {pdf_path}: {str(e)}")
        return None

def process_file(file_path):
    """Process a single file (image or PDF) to decode QR code."""
    file_path = Path(file_path)
    if not file_path.exists():
        print(f"File not found: {file_path}")
        return None

    if file_path.suffix.lower() in [".pdf"]:
        return decode_qr_from_pdf(file_path)
    elif file_path.suffix.lower() in [".png", ".jpg", ".jpeg"]:
        return decode_qr_from_image(file_path)
    else:
        print(f"Unsupported file type: {file_path.suffix}")
        return None

def process_directory(directory_path):
    """Process all PDF and image files in a directory."""
    directory_path = Path(directory_path)
    if not directory_path.is_dir():
        print(f"Directory not found: {directory_path}")
        return

    supported_extensions = {".pdf", ".png", ".jpg", ".jpeg"}
    for file_path in directory_path.iterdir():
        if file_path.suffix.lower() in supported_extensions:
            print(f"\nProcessing {file_path}")
            process_file(file_path)

def main():
    """Main function to handle command-line arguments and process files."""
    parser = argparse.ArgumentParser(description="Decode QR codes from images or PDFs.")
    parser.add_argument("-i", "--input", type=str, help="Path to a single image or PDF file")
    parser.add_argument("-d", "--directory", type=str, help="Path to a directory containing images or PDFs")

    args = parser.parse_args()

    if args.input:
        qr_data = process_file(args.input)
        if qr_data:
            print(f"\nDecoded QR Code Data: {qr_data}")
        else:
            print("\nNo QR code data found.")
    elif args.directory:
        process_directory(args.directory)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()