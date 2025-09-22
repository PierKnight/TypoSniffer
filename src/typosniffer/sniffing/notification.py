
import csv
from datetime import datetime
import io
from typosniffer.config.config import get_config
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.sniffing.monitor import DomainReport
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils import email

def notify_new_suspicious_domains(scan_date: datetime, sniff_results: list[SniffResult]):

    html = email.get_body(get_config().email.discovery_template, {"results": sniff_results, "scan_date": scan_date})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Suspicious Domain", "Original Domain"])

    for d in sniff_results:
        writer.writerow([d.domain, d.original_domain])
        
    email.send_email("Suspicious Domains Update", text="test", html_body=html, attachments=[('new_suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')])

def notify_inspection_suspicious_domains(inspection_date: datetime, suspicious_domains: list[SuspiciousDomainDTO], reports: list[DomainReport]):



    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Suspicious Domain", "Website Url", "Status", "Similary Original Website"])
    
    for report in reports:
        
        if report.update_report is not None:
        
            website_url = report.update_report.url if report.update_report else None
            status = report.update_report.status.name if report.update_report else None
            similarity = report.phishing_report.hash_similarity if report.phishing_report else -1
            writer.writerow([report.suspicious_domain.name, website_url, status, f"{similarity:.1f}"])
    
    attachments = []
    if len(reports) > 0:
        attachments = [('inspection_suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')]


    html = email.get_body(get_config().email.inspection_template, {'reports': reports, 'date': inspection_date, 'suspicious_domains': suspicious_domains})
    email.send_email('Suspicious Domain Inspection', "", html, attachments=attachments)


def error_notification(failed_task: str):
    html = email.get_body({"task": failed_task, "date": datetime.now()})