
import asyncio
import csv
from datetime import datetime
import io
from typosniffer.config.config import get_config
from typosniffer.data.dto import SuspiciousDomainDTO
from typosniffer.sniffing.monitor import DomainReport
from typosniffer.sniffing.sniffer import SniffResult
from typosniffer.utils import console, email, imgbb, logger


def _check_email_config(task: str) -> bool:

    if not email.is_configured():
        console.print_warning(f"Email is not configured! Skipping: '{task}' notification")
        logger.log.warning(f"Skipping '{task}' email notification: email configuration is not defined")
        return True
    return False    

def notify_new_suspicious_domains(scan_date: datetime, sniff_results: list[SniffResult]):

    if _check_email_config('Discovery Suspicious Domains'):
        return

    html = email.get_body(get_config().email.discovery_template, {"results": sniff_results, "scan_date": scan_date})

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Suspicious Domain", "Original Domain"])

    for d in sniff_results:
        writer.writerow([d.domain, d.original_domain])
        
    email.send_email("Suspicious Domains Update", text="test", html_body=html, attachments=[('new_suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')])

def notify_inspection_suspicious_domains(inspection_date: datetime, suspicious_domains: list[SuspiciousDomainDTO], reports: list[DomainReport]):

    if _check_email_config('Inspection Suspicious Domains'):
        return
    
    columns = ["Suspicious Domain", "Website Url", "Status", "Similarity Original Website"]

    upload_config = get_config().email.imgbb
    upload_screenshots = upload_config is not None

    if not upload_screenshots:
        console.print_warning("images will not be added to the results")
        logger.log.warning("Image upload service not configured")
    else:
        columns.insert(3, "Screenshot URL")

    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(columns)
    
    updated_reports = []

    async def process_report(report: DomainReport):
        name = report.suspicious_domain.name
        website_url = report.update_report.url if report.update_report else None
        status = report.update_report.status.name if report.update_report else None
        similarity = report.phishing_report.cnn_similarity if report.phishing_report else -1

        if upload_screenshots:
            screenshot_url = await asyncio.to_thread(imgbb.upload_screenshot, report.suspicious_domain, report.update_report.date, upload_config)
            return [name, website_url, status, screenshot_url, f"{similarity:.1f}"]
        return [name, website_url, status, f"{similarity:.1f}"]

    # Collect tasks for all reports that need processing
    updated_reports = [report for report in reports if report.update_report is not None]
    tasks = [process_report(report) for report in updated_reports]

    async def process_reports(): return await asyncio.gather(*tasks)
    
    with console.status("Processing Reports to send"):
        # Run the async uploads and get results
        results = asyncio.run(process_reports())

    # Write CSV rows
    for row in results:
        writer.writerow(row)

    attachments = []
    if reports:
        attachments = [('inspection_suspicious_domains.csv', output.getvalue().encode("utf-8"), 'txt', 'csv')]

    html = email.get_body(get_config().email.inspection_template, {
        'reports': updated_reports,
        'date': inspection_date,
        'suspicious_domains': suspicious_domains
    })
    email.send_email('Suspicious Domain Inspection', "", html, attachments=attachments)


def error_notification(failed_task: str):
    html = email.get_body({"task": failed_task, "date": datetime.now()})