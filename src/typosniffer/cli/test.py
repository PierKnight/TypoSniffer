import csv
import datetime
import io
from pathlib import Path
from PIL import Image
import click
import imagehash

from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.sniffing import cnn

from typosniffer.utils.email import get_body, send_email


@click.command
@click.argument("file1", type=click.Path(file_okay=True))
@click.argument("file2", type=click.Path(file_okay=True))
def compare(file1: Path, file2: Path):

    hash_def = imagehash.dhash

    size = 8
    image1 = Image.open(file1)
    image2 = Image.open(file2)
    hash1 = hash_def(image1, hash_size=size)
    hash2 = hash_def(image2, hash_size=size)

    hash1 = imagehash.hex_to_hash(str(hash1))
    hash2 = imagehash.hex_to_hash(str(hash2))

    print(f"SIMILARITY HASH {1 - (hash2 - hash1) / (size * 8)}")

    cnn_comparator = cnn.ImageComparator()

    print(f"SIMILARITY CNN {cnn_comparator.get_similarity(image1, image2)}")

@click.command
def email():


    domains = [SuspiciousDomainDTO(id=344, name="pepo.it", original_domain="google.com")]

    
    html = get_body({"domains": domains, "scan_date": datetime.datetime.now()})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Id", "Suspicious Domain", "Original Domain"])

    for d in domains:
        writer.writerow([d.id, d.name, d.original_domain])
        
    send_email("Suspicious Domains Update", text="test", html_body=html, attachments=[('suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')])
