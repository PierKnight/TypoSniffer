import logging
from logging.handlers import TimedRotatingFileHandler

from typosniffer.config import config

# Directory for logs
log_dir = config.FOLDER / "logs"
log_dir.mkdir(exist_ok=True)

# File handler: rotates every day at midnight
file_handler = TimedRotatingFileHandler(
    log_dir / "typosniffer.log",
    when="midnight",   
    interval=1,
    backupCount=7         
)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s")
)

# Console handler (Rich)
#console_handler = RichHandler(rich_tracebacks=True)

# Logger setup
log = logging.getLogger("typosniffer")
log.setLevel(logging.INFO)
log.addHandler(file_handler)

