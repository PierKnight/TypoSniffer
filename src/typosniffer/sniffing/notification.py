
import csv
from datetime import datetime
import io
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils import email

def notify_new_suspicious_domains(scan_date: datetime, sniff_results: list[SniffResult]):

    html = email.get_body({"results": sniff_results, "scan_date": scan_date})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Suspicious Domain", "Original Domain"])

    for d in sniff_results:
        writer.writerow([d.domain, d.original_domain])
        
    email.send_email("Suspicious Domains Update", text="test", html_body=html, attachments=[('suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')])

def error_notification(failed_task: str):
    html = email.get_body({"task": failed_task, "date": datetime.now()})