from pathlib import Path
from PIL import Image
import click
import imagehash
import whois
from typosniffer.sniffing import cnn

@click.group
def test():
    pass

@test.command
@click.argument("file1", type=click.Path(file_okay=True))
@click.argument("file2", type=click.Path(file_okay=True))
def compare(file1: Path, file2: Path):

    hash_def = imagehash.phash

    size = 16
    image1 = Image.open(file1)
    image2 = Image.open(file2)
    hash1 = hash_def(image1, hash_size=size)
    hash2 = hash_def(image2, hash_size=size)

    hash1 = imagehash.hex_to_hash(str(hash1))
    hash2 = imagehash.hex_to_hash(str(hash2))

    
    cnn_comparator = cnn.ImageComparator()

    print(f"JUST HASH {hash2 - hash1}")
    print(f"SIMILARITY HASH {1 - (hash2 - hash1) / (size)**2}")
    print(f"SIMILARITY CNN {cnn_comparator.get_similarity(image1, image2)}")

@test.command()
def who():
    print(whois.whois('gooogle.su'))