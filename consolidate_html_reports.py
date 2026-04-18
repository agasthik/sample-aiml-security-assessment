#!/usr/bin/env python3
"""
Multi-account HTML report consolidation script.

This script is executed during CodeBuild post-build phase to consolidate
HTML reports from multiple AWS accounts into a single report.

It uses the shared report_template module from the Lambda function directory.
"""
import os
import sys
import glob
import boto3
from bs4 import BeautifulSoup
from datetime import datetime
from botocore.exceptions import ClientError

# Add the Lambda function directory to path to import shared template
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'resco-aiml-assessment', 'functions', 'security', 'generate_consolidated_report'))

from report_template import generate_html_report

def consolidate_html_reports():
    """Consolidate HTML reports from all accounts into a single report using shared template"""

    try:
        s3 = boto3.client('s3')
    except Exception as e:
        print(f"Error creating S3 client: {str(e)}")
        raise

    bucket = os.environ.get('BUCKET_REPORT')
    if not bucket:
        print("Error: BUCKET_REPORT environment variable is not set")
        raise ValueError("BUCKET_REPORT environment variable is required")

    all_findings = []
    account_ids = set()
    service_stats = {'bedrock': {'passed': 0, 'failed': 0}, 'sagemaker': {'passed': 0, 'failed': 0}, 'agentcore': {'passed': 0, 'failed': 0}}
    service_findings = {'bedrock': [], 'sagemaker': [], 'agentcore': []}

    for account_dir in glob.glob('/tmp/account-files/*/'):
        account_id = os.path.basename(account_dir.rstrip('/'))
        if account_id == 'consolidated-reports':
            continue

        html_files = glob.glob(os.path.join(account_dir, '**/security_assessment_*.html'), recursive=True)

        if html_files:
            print(f"Processing HTML files for account {account_id}")
            account_ids.add(account_id)

            try:
                with open(html_files[0], 'r') as f:
                    soup = BeautifulSoup(f.read(), 'html.parser')
            except IOError as e:
                print(f"Error reading HTML file for account {account_id}: {str(e)}")
                continue
            except Exception as e:
                print(f"Error parsing HTML for account {account_id}: {str(e)}")
                continue

            tbody = soup.find('tbody')
            if tbody:
                rows = tbody.find_all('tr')
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 8:
                        finding = {
                            'account_id': account_id,
                            'check_id': cells[1].get_text(strip=True) if len(cells) > 1 else '',
                            'finding': cells[2].get_text(strip=True) if len(cells) > 2 else '',
                            'details': cells[3].get_text(strip=True) if len(cells) > 3 else '',
                            'resolution': cells[4].get_text(strip=True) if len(cells) > 4 else '',
                            'reference': '',
                            'severity': cells[6].get_text(strip=True) if len(cells) > 6 else '',
                            'status': cells[7].get_text(strip=True) if len(cells) > 7 else ''
                        }
                        ref_cell = cells[5] if len(cells) > 5 else None
                        if ref_cell:
                            links = ref_cell.find_all('a')
                            if links:
                                finding['reference'] = links[0].get('href', '')
                            else:
                                finding['reference'] = ref_cell.get_text(strip=True)

                        check_id = finding.get('check_id', '').upper()
                        status = finding['status'].lower()
                        if check_id.startswith('BR-'):
                            service = 'bedrock'
                        elif check_id.startswith('SM-'):
                            service = 'sagemaker'
                        elif check_id.startswith('AC-'):
                            service = 'agentcore'
                        else:
                            finding_name = finding['finding'].lower()
                            if 'bedrock' in finding_name or 'guardrail' in finding_name:
                                service = 'bedrock'
                            elif 'sagemaker' in finding_name or 'domain' in finding_name:
                                service = 'sagemaker'
                            elif 'agentcore' in finding_name:
                                service = 'agentcore'
                            else:
                                service = 'bedrock'

                        finding['_service'] = service
                        all_findings.append(finding)
                        service_findings[service].append(finding)

                        if status == 'passed':
                            service_stats[service]['passed'] += 1
                        elif status == 'failed':
                            service_stats[service]['failed'] += 1

    if all_findings:
        timestamp_display = datetime.now().strftime('%B %d, %Y %H:%M:%S UTC')

        # Use shared template to generate report
        consolidated_html = generate_html_report(
            all_findings=all_findings,
            service_findings=service_findings,
            service_stats=service_stats,
            mode='multi',
            account_ids=list(account_ids),
            timestamp=timestamp_display
        )

        timestamp_file = datetime.now().strftime('%Y%m%d_%H%M%S')
        s3_key = f'consolidated-reports/multi_account_report_{timestamp_file}.html'

        try:
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=consolidated_html,
                ContentType='text/html'
            )
            print(f'Consolidated report saved to s3://{bucket}/{s3_key}')
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                print(f"Error: Bucket '{bucket}' does not exist")
            elif error_code == 'AccessDenied':
                print(f"Error: Access denied to bucket '{bucket}'")
            else:
                print(f"Error uploading to S3: {str(e)}")
            raise
        except Exception as e:
            print(f"Unexpected error uploading consolidated report: {str(e)}")
            raise
    else:
        print('No HTML reports found for consolidation')
        for account_dir in glob.glob('/tmp/account-files/*/'):
            account_id = os.path.basename(account_dir.rstrip('/'))
            all_files = glob.glob(os.path.join(account_dir, '**/*'), recursive=True)
            print(f"Account {account_id} files: {all_files}")

if __name__ == '__main__':
    consolidate_html_reports()
