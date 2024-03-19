import os
from PyPDF2 import PdfReader, PdfWriter
import argparse

parser = argparse.ArgumentParser(description='Split PDF file into batch of 100 pages PDFs.')
parser.add_argument('--input', help='the input directory', required=True)
parser.add_argument('--dest', help='the destination', required=True)

def split_pdf(in_dir, out_dir, file):
    # Read the original PDF
    filename = os.path.join(in_dir, file)
    input_pdf = PdfReader(filename)

    batch_size = 100
    num_batches = len(input_pdf.pages) // batch_size + 1

    # Extract batches of 100 pages from the PDF
    for b in range(num_batches):
        writer = PdfWriter()

        # Get the start and end page numbers for this batch
        start_page = b * batch_size
        end_page = min((b+1) * batch_size, len(input_pdf.pages))

        # Add pages in this batch to the writer
        for i in range(start_page, end_page):
            writer.add_page(input_pdf.pages[i])

        # Save the batch to a separate PDF file
        
        batch_filename = os.path.join(out_dir, file.replace(".pdf", "-") + str (b+1) + '.pdf')
        print(batch_filename)
        with open(batch_filename, 'wb') as output_file:
            writer.write(output_file)


args = parser.parse_args()

for file in os.listdir(args.input):
    print(file)
    try:
        split_pdf(args.input, args.dest, file)
    except Exception as e:
        print(e)
        continue