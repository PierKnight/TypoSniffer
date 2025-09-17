import datetime
from pathlib import Path
from PIL import Image
import click
import imagehash

from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.sniffing import cnn
from typosniffer.sniffing.monitor import DomainReport, PhishingReport, UpdateReport

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


    reports = []

    for i in range(2):
        reports.append(DomainReport(
            phishing_report=PhishingReport(cnn_similarity= 0.6, hash_similarity=0.7),
            suspicious_domain=SuspiciousDomainDTO(id=1, name="g00gle.com", original_domain="google.com"),
            update_report=UpdateReport(date=datetime.datetime.now(), url= "https://g00gle.com/sos")
        ))

    html = get_body({"reports": reports})

    send_email("Suspicious Domains Update", html)
