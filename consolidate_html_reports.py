#!/usr/bin/env python3
import os
import glob
import boto3
import re
from bs4 import BeautifulSoup
from datetime import datetime
from botocore.exceptions import ClientError

def consolidate_html_reports():
    """Consolidate HTML reports from all accounts into a single report with sidebar navigation design"""

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
        total_findings = len(all_findings)
        high_count = sum(1 for f in all_findings if f['severity'].lower() == 'high')
        medium_count = sum(1 for f in all_findings if f['severity'].lower() == 'medium')
        low_count = sum(1 for f in all_findings if f['severity'].lower() == 'low')
        passed_count = sum(1 for f in all_findings if f['status'].lower() == 'passed')
        pass_rate = round((passed_count / total_findings * 100), 1) if total_findings > 0 else 0

        timestamp_display = datetime.now().strftime('%B %d, %Y %H:%M:%S UTC')
        date_display = datetime.now().strftime('%B %d, %Y')

        high_priority = [f for f in all_findings if f['severity'].lower() == 'high' and f['status'].lower() == 'failed']
        medium_priority = [f for f in all_findings if f['severity'].lower() == 'medium' and f['status'].lower() == 'failed']

        alerts_html = ""
        alert_groups = {}
        for f in high_priority[:4]:
            key = f.get('finding', '')
            if key not in alert_groups:
                alert_groups[key] = {'count': 0, 'finding': f}
            alert_groups[key]['count'] += 1

        for key, data in list(alert_groups.items())[:3]:
            f = data['finding']
            service_name = 'Bedrock' if f.get('_service') == 'bedrock' else 'SageMaker' if f.get('_service') == 'sagemaker' else 'AgentCore'
            alerts_html += f'''<div class="alert-item critical">
                <div class="alert-count">{data['count']}</div>
                <div class="alert-info">
                    <div class="alert-domain">{f.get('finding', '')}</div>
                    <div class="alert-category">{service_name}</div>
                </div>
            </div>'''

        for f in medium_priority[:1]:
            service_name = 'Bedrock' if f.get('_service') == 'bedrock' else 'SageMaker' if f.get('_service') == 'sagemaker' else 'AgentCore'
            alerts_html += f'''<div class="alert-item warning">
                <div class="alert-count">1</div>
                <div class="alert-info">
                    <div class="alert-domain">{f.get('finding', '')}</div>
                    <div class="alert-category">{service_name}</div>
                </div>
            </div>'''

        if not alerts_html:
            alerts_html = '<div class="alert-item"><div class="alert-info"><div class="alert-domain">No critical findings</div></div></div>'

        account_options = ''.join([f'<option value="{acc}">{acc}</option>' for acc in sorted(account_ids)])

        def generate_table_rows(findings, include_service_data=True):
            rows = []
            for f in findings:
                severity = f['severity'].lower()
                severity_class = severity if severity in ['high', 'medium', 'low'] else 'na'
                status = f['status'].lower()
                status_class = 'passed' if status == 'passed' else 'na' if status == 'n/a' else 'failed'
                service = f.get('_service', 'bedrock')

                ref = f.get('reference', '')
                if ref and ref.strip() and ref.strip() != '-':
                    ref_html = f'''<a href="{ref}" target="_blank" class="reference-btn" title="View AWS Documentation"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg></a>'''
                else:
                    ref_html = '<span style="color: var(--text-3);">-</span>'

                data_attrs = f'data-service="{service}" data-severity="{severity}" data-status="{status}" data-account="{f.get("account_id", "")}"' if include_service_data else ''

                row = f'''<tr {data_attrs}>
                    <td><code>{f.get('account_id', '')}</code></td>
                    <td><code>{f.get('check_id', '')}</code></td>
                    <td class="col-domain">{f.get('finding', '')}</td>
                    <td class="finding-details">{f.get('details', '')}</td>
                    <td class="resolution-text">{f.get('resolution', '')}</td>
                    <td class="reference-cell">{ref_html}</td>
                    <td><span class="severity {severity_class}">{f.get('severity', 'N/A')}</span></td>
                    <td><span class="status {'success' if status_class == 'passed' else 'error' if status_class == 'failed' else 'warning'}">{f.get('status', '')}</span></td>
                </tr>'''
                rows.append(row)
            return '\n'.join(rows) if rows else '<tr><td colspan="8" style="text-align: center; padding: 40px; color: var(--text-3);">No findings to display</td></tr>'

        all_rows = generate_table_rows(all_findings)
        bedrock_rows = generate_table_rows(service_findings['bedrock'], False)
        sagemaker_rows = generate_table_rows(service_findings['sagemaker'], False)
        agentcore_rows = generate_table_rows(service_findings['agentcore'], False)

        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Account AI/ML Security Assessment Report</title>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #fff;
            --surface-2: #f1f5f9;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-2: #64748b;
            --text-3: #94a3b8;
            --accent: #6366f1;
            --accent-soft: #eef2ff;
            --success: #10b981;
            --success-soft: #ecfdf5;
            --warning: #f59e0b;
            --warning-soft: #fffbeb;
            --danger: #ef4444;
            --danger-soft: #fef2f2;
        }}
        [data-theme="dark"] {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-2: #334155;
            --border: #475569;
            --text: #f1f5f9;
            --text-2: #94a3b8;
            --text-3: #64748b;
            --accent: #818cf8;
            --accent-soft: rgba(129, 140, 248, 0.15);
            --success: #4ade80;
            --success-soft: rgba(74, 222, 128, 0.15);
            --warning: #fbbf24;
            --warning-soft: rgba(251, 191, 36, 0.15);
            --danger: #f87171;
            --danger-soft: rgba(248, 113, 113, 0.15);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'DM Sans', system-ui, sans-serif; font-size: 14px; line-height: 1.6; color: var(--text); background: var(--bg); -webkit-font-smoothing: antialiased; }}
        .layout {{ display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }}
        .sidebar {{ background: var(--surface); border-right: 1px solid var(--border); padding: 24px 0; position: sticky; top: 0; height: 100vh; overflow-y: auto; display: flex; flex-direction: column; }}
        .sidebar-header {{ padding: 0 20px 24px; border-bottom: 1px solid var(--border); margin-bottom: 16px; }}
        .sidebar-header h1 {{ font-size: 18px; font-weight: 700; color: var(--text); margin-bottom: 4px; }}
        .sidebar-header p {{ font-size: 12px; color: var(--text-3); }}
        .theme-toggle {{ display: flex; align-items: center; gap: 8px; margin: 16px 20px; padding: 10px 14px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 500; color: var(--text); transition: all 0.15s; }}
        .theme-toggle:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
        .theme-toggle svg {{ width: 18px; height: 18px; }}
        .theme-toggle .sun-icon {{ display: none; }}
        .theme-toggle .moon-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .sun-icon {{ display: block; }}
        [data-theme="dark"] .theme-toggle .moon-icon {{ display: none; }}
        .nav-section {{ padding: 0 16px; margin-bottom: 24px; }}
        .nav-section h3 {{ font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; padding: 0 8px; margin-bottom: 8px; }}
        .nav-item {{ display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 8px; color: var(--text-2); font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.15s; text-decoration: none; }}
        .nav-item:hover {{ background: var(--surface-2); color: var(--text); }}
        .nav-item.active {{ background: var(--accent-soft); color: var(--accent); }}
        .nav-item svg {{ width: 18px; height: 18px; opacity: 0.7; flex-shrink: 0; }}
        .service-badge {{ display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 6px; font-size: 12px; font-weight: 700; color: white; flex-shrink: 0; }}
        .service-badge.bedrock {{ background: linear-gradient(135deg, #2E7D32 0%, #66BB6A 100%); }}
        .service-badge.sagemaker {{ background: linear-gradient(135deg, #00695C 0%, #26A69A 100%); }}
        .service-badge.agentcore {{ background: linear-gradient(135deg, #5E35B1 0%, #9575CD 100%); }}
        .section-title .service-badge {{ width: 32px; height: 32px; font-size: 14px; border-radius: 8px; }}
        .nav-item .count {{ margin-left: auto; font-size: 12px; font-weight: 600; background: var(--surface-2); padding: 2px 8px; border-radius: 10px; }}
        .nav-item.active .count {{ background: var(--accent); color: #fff; }}
        .sidebar-footer {{ margin-top: auto; padding: 16px 20px; border-top: 1px solid var(--border); font-size: 12px; color: var(--text-3); }}
        .sidebar-footer a {{ color: var(--accent); text-decoration: none; }}
        .main {{ padding: 32px 40px; max-width: 1400px; }}
        .page-header {{ margin-bottom: 32px; }}
        .page-header h2 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; }}
        .page-header-meta {{ display: flex; gap: 24px; font-size: 13px; color: var(--text-2); }}
        .page-header-meta span {{ display: flex; align-items: center; gap: 6px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
        .metric {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }}
        .metric-label {{ font-size: 13px; color: var(--text-2); margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }}
        .metric-value {{ font-size: 28px; font-weight: 700; color: var(--text); }}
        .metric-sub {{ font-size: 12px; color: var(--text-3); margin-top: 4px; }}
        .metric.highlight {{ background: linear-gradient(135deg, var(--success-soft) 0%, rgba(16, 185, 129, 0.2) 100%); border-color: var(--success); }}
        .metric.highlight .metric-value {{ color: var(--success); }}
        .metric.danger .metric-value {{ color: var(--danger); }}
        .metric.warning .metric-value {{ color: var(--warning); }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 24px; }}
        .card-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
        .card-header h3 {{ font-size: 15px; font-weight: 600; display: flex; align-items: center; gap: 10px; }}
        .card-body {{ padding: 20px; }}
        .alerts {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }}
        .alert-item {{ display: flex; align-items: center; gap: 12px; padding: 12px 16px; border-radius: 8px; background: var(--surface-2); cursor: pointer; transition: all 0.15s; }}
        .alert-item:hover {{ background: var(--border); }}
        .alert-item.critical {{ background: var(--danger-soft); border-left: 3px solid var(--danger); }}
        .alert-item.warning {{ background: var(--warning-soft); border-left: 3px solid var(--warning); }}
        .alert-count {{ font-size: 20px; font-weight: 700; min-width: 32px; text-align: center; }}
        .alert-item.critical .alert-count {{ color: var(--danger); }}
        .alert-item.warning .alert-count {{ color: var(--warning); }}
        .alert-info {{ flex: 1; min-width: 0; }}
        .alert-domain {{ font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .alert-category {{ font-size: 12px; color: var(--text-2); margin-top: 2px; }}
        .table-wrap {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; table-layout: fixed; min-width: 900px; }}
        table th:nth-child(1) {{ width: 11%; }}
        table th:nth-child(2) {{ width: 7%; }}
        table th:nth-child(3) {{ width: 13%; }}
        table th:nth-child(4) {{ width: 20%; }}
        table th:nth-child(5) {{ width: 20%; }}
        table th:nth-child(6) {{ width: 7%; }}
        table th:nth-child(7) {{ width: 10%; }}
        table th:nth-child(8) {{ width: 10%; }}
        th {{ text-align: left; padding: 14px 16px; font-weight: 700; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text); background: var(--surface-2); border-bottom: 2px solid var(--border); white-space: nowrap; position: sticky; top: 0; }}
        th:nth-last-child(-n+3), td:nth-last-child(-n+3) {{ text-align: center; }}
        td {{ padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: top; line-height: 1.5; word-wrap: break-word; overflow-wrap: break-word; }}
        tr:hover td {{ background: var(--surface-2); }}
        .col-domain {{ font-weight: 500; color: var(--text); }}
        .status {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; font-family: 'JetBrains Mono', monospace; }}
        .status.success {{ background: var(--success-soft); color: var(--success); }}
        .status.error {{ background: var(--danger-soft); color: var(--danger); }}
        .status.warning {{ background: var(--warning-soft); color: var(--warning); }}
        .severity {{ display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
        .severity.high {{ background: var(--danger-soft); color: var(--danger); }}
        .severity.medium {{ background: var(--warning-soft); color: var(--warning); }}
        .severity.low {{ background: var(--accent-soft); color: var(--accent); }}
        .severity.na {{ background: var(--surface-2); color: var(--text-3); }}
        .filter-bar {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; align-items: flex-end; }}
        .filter-group {{ display: flex; flex-direction: column; gap: 4px; }}
        .filter-group label {{ font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.3px; }}
        .filter-group input, .filter-group select {{ padding: 8px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 13px; font-family: inherit; background: var(--surface); color: var(--text); min-width: 160px; transition: border-color 0.15s; }}
        .filter-group input:focus, .filter-group select:focus {{ outline: none; border-color: var(--accent); }}
        .btn {{ display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; font-family: inherit; cursor: pointer; transition: all 0.15s; border: none; }}
        .btn svg {{ width: 16px; height: 16px; }}
        .btn-reset {{ background: var(--surface); color: var(--text-2); border: 1px solid var(--border); padding: 8px 14px; }}
        .btn-reset:hover {{ background: var(--danger-soft); color: var(--danger); border-color: var(--danger); }}
        .section {{ scroll-margin-top: 20px; margin-bottom: 40px; }}
        .section-title {{ font-size: 18px; font-weight: 700; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid var(--border); display: flex; align-items: center; gap: 12px; }}
        code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; background: var(--surface-2); padding: 2px 6px; border-radius: 4px; white-space: nowrap; }}
        .reference-cell {{ text-align: center; }}
        .reference-btn {{ display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; background: var(--accent-soft); color: var(--accent); text-decoration: none; border-radius: 6px; border: 1px solid var(--border); transition: all 0.15s; }}
        .reference-btn:hover {{ background: var(--accent); color: white; border-color: var(--accent); }}
        .reference-btn svg {{ width: 14px; height: 14px; }}
        .finding-details {{ color: var(--text-2); font-size: 12px; line-height: 1.6; word-break: break-word; overflow-wrap: break-word; hyphens: auto; }}
        .resolution-text {{ color: var(--text-2); font-size: 12px; line-height: 1.6; word-break: break-word; overflow-wrap: break-word; hyphens: auto; }}
        @media (max-width: 1024px) {{ .layout {{ grid-template-columns: 1fr; }} .sidebar {{ display: none; }} .metrics {{ grid-template-columns: repeat(2, 1fr); }} }}
        @media (max-width: 640px) {{ .metrics {{ grid-template-columns: 1fr; }} .main {{ padding: 20px; }} }}
    </style>
</head>
<body>
    <div class="layout">
        <aside class="sidebar">
            <div class="sidebar-header">
                <h1>AI/ML Security</h1>
                <p>Multi-Account Assessment</p>
            </div>
            <button class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
                <svg class="moon-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/></svg>
                <svg class="sun-icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/></svg>
                <span class="theme-label">Dark Mode</span>
            </button>
            <nav class="nav-section">
                <h3>Navigation</h3>
                <a href="#overview" class="nav-item active">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
                    Overview
                </a>
                <a href="#findings" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Security Findings
                    <span class="count">{total_findings}</span>
                </a>
                <a href="#risk" class="nav-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Risk Distribution
                </a>
            </nav>
            <nav class="nav-section">
                <h3>By Service</h3>
                <a href="#bedrock" class="nav-item">
                    <span class="service-badge bedrock">B</span>
                    Bedrock
                    <span class="count">{bedrock_total}</span>
                </a>
                <a href="#sagemaker" class="nav-item">
                    <span class="service-badge sagemaker">S</span>
                    SageMaker
                    <span class="count">{sagemaker_total}</span>
                </a>
                <a href="#agentcore" class="nav-item">
                    <span class="service-badge agentcore">A</span>
                    AgentCore
                    <span class="count">{agentcore_total}</span>
                </a>
            </nav>
            <div class="sidebar-footer">
                <p>Generated: {date_display}</p>
                <p>Accounts: {num_accounts}</p>
                <p style="margin-top: 8px;"><a href="https://github.com/aws-samples/sample-resco-aiml-assessment">GitHub Repository</a></p>
            </div>
        </aside>
        <main class="main">
            <section id="overview" class="section">
                <div class="page-header">
                    <h2>Security Assessment Overview</h2>
                    <div class="page-header-meta">
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>{timestamp}</span>
                        <span><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>{num_accounts} Accounts</span>
                    </div>
                </div>
                <div class="metrics">
                    <div class="metric"><div class="metric-label">Total Findings</div><div class="metric-value">{total_findings}</div><div class="metric-sub">Across all services</div></div>
                    <div class="metric danger"><div class="metric-label">High Severity</div><div class="metric-value">{high_count}</div><div class="metric-sub">Requires immediate attention</div></div>
                    <div class="metric warning"><div class="metric-label">Medium Severity</div><div class="metric-value">{medium_count}</div><div class="metric-sub">Should be addressed</div></div>
                    <div class="metric highlight"><div class="metric-label">Passed Checks</div><div class="metric-value">{passed_count}</div><div class="metric-sub">{pass_rate}% pass rate</div></div>
                </div>
                <div class="card"><div class="card-header"><h3>Priority Recommendations</h3></div><div class="card-body"><div class="alerts">{alerts}</div></div></div>
            </section>
            <section id="findings" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>All Security Findings</div>
                <div class="filter-bar">
                    <div class="filter-group"><label>Search</label><input type="text" placeholder="Search findings..." id="searchInput"></div>
                    <div class="filter-group"><label>Account</label><select id="accountFilter"><option value="">All Accounts</option>{account_options}</select></div>
                    <div class="filter-group"><label>Service</label><select id="serviceFilter"><option value="">All Services</option><option value="bedrock">Bedrock</option><option value="sagemaker">SageMaker</option><option value="agentcore">AgentCore</option></select></div>
                    <div class="filter-group"><label>Severity</label><select id="severityFilter"><option value="">All Severities</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
                    <div class="filter-group"><label>Status</label><select id="statusFilter"><option value="">All Statuses</option><option value="failed">Failed</option><option value="passed">Passed</option></select></div>
                    <button class="btn btn-reset" id="resetFilters"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>Reset</button>
                </div>
                <div class="card"><div class="table-wrap"><table id="findingsTable"><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{all_rows}</tbody></table></div></div>
            </section>
            <section id="risk" class="section">
                <div class="section-title"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Risk Distribution</div>
                <div class="metrics">
                    <div class="metric"><div class="metric-label">Bedrock</div><div class="metric-value">{bedrock_total}</div><div class="metric-sub">{bedrock_failed} Failed, {bedrock_passed} Passed</div></div>
                    <div class="metric"><div class="metric-label">SageMaker</div><div class="metric-value">{sagemaker_total}</div><div class="metric-sub">{sagemaker_failed} Failed, {sagemaker_passed} Passed</div></div>
                    <div class="metric"><div class="metric-label">AgentCore</div><div class="metric-value">{agentcore_total}</div><div class="metric-sub">{agentcore_failed} Failed, {agentcore_passed} Passed</div></div>
                    <div class="metric highlight"><div class="metric-label">Pass Rate</div><div class="metric-value">{pass_rate}%</div><div class="metric-sub">{passed_count} of {total_findings} checks passed</div></div>
                </div>
            </section>
            <section id="bedrock" class="section">
                <div class="section-title"><span class="service-badge bedrock">B</span>Amazon Bedrock Findings</div>
                <div class="card"><div class="table-wrap"><table><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{bedrock_rows}</tbody></table></div></div>
            </section>
            <section id="sagemaker" class="section">
                <div class="section-title"><span class="service-badge sagemaker">S</span>Amazon SageMaker Findings</div>
                <div class="card"><div class="table-wrap"><table><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{sagemaker_rows}</tbody></table></div></div>
            </section>
            <section id="agentcore" class="section">
                <div class="section-title"><span class="service-badge agentcore">A</span>Amazon Bedrock AgentCore Findings</div>
                <div class="card"><div class="table-wrap"><table><thead><tr><th>Account ID</th><th>Check ID</th><th>Finding</th><th>Details</th><th>Resolution</th><th>Reference</th><th>Severity</th><th>Status</th></tr></thead><tbody>{agentcore_rows}</tbody></table></div></div>
            </section>
        </main>
    </div>
    <script>
        const themeToggle = document.getElementById('themeToggle');
        const themeLabel = themeToggle.querySelector('.theme-label');
        const html = document.documentElement;
        const savedTheme = localStorage.getItem('theme') || 'light';
        if (savedTheme === 'dark') {{ html.setAttribute('data-theme', 'dark'); themeLabel.textContent = 'Light Mode'; }}
        themeToggle.addEventListener('click', function() {{
            const currentTheme = html.getAttribute('data-theme');
            if (currentTheme === 'dark') {{ html.removeAttribute('data-theme'); localStorage.setItem('theme', 'light'); themeLabel.textContent = 'Dark Mode'; }}
            else {{ html.setAttribute('data-theme', 'dark'); localStorage.setItem('theme', 'dark'); themeLabel.textContent = 'Light Mode'; }}
        }});
        document.querySelectorAll('.nav-item').forEach(item => {{
            item.addEventListener('click', function(e) {{
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetSection = document.querySelector(targetId);
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                if (targetSection) {{ targetSection.scrollIntoView({{ behavior: 'smooth' }}); }}
            }});
        }});
        function applyFilters() {{
            const searchText = document.getElementById('searchInput').value.toLowerCase();
            const accountFilter = document.getElementById('accountFilter').value.toLowerCase();
            const serviceFilter = document.getElementById('serviceFilter').value.toLowerCase();
            const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
            const statusFilter = document.getElementById('statusFilter').value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTable tbody tr');
            rows.forEach(row => {{
                const rowText = row.textContent.toLowerCase();
                const rowAccount = row.dataset.account || '';
                const rowService = row.dataset.service || '';
                const rowSeverity = row.dataset.severity || '';
                const rowStatus = row.dataset.status || '';
                let show = true;
                if (searchText && !rowText.includes(searchText)) show = false;
                if (accountFilter && rowAccount !== accountFilter) show = false;
                if (serviceFilter && rowService !== serviceFilter) show = false;
                if (severityFilter && rowSeverity !== severityFilter) show = false;
                if (statusFilter && rowStatus !== statusFilter) show = false;
                row.style.display = show ? '' : 'none';
            }});
        }}
        document.getElementById('resetFilters').addEventListener('click', function() {{
            document.getElementById('searchInput').value = '';
            document.getElementById('accountFilter').value = '';
            document.getElementById('serviceFilter').value = '';
            document.getElementById('severityFilter').value = '';
            document.getElementById('statusFilter').value = '';
            applyFilters();
        }});
        document.getElementById('searchInput').addEventListener('input', applyFilters);
        document.getElementById('accountFilter').addEventListener('change', applyFilters);
        document.getElementById('serviceFilter').addEventListener('change', applyFilters);
        document.getElementById('severityFilter').addEventListener('change', applyFilters);
        document.getElementById('statusFilter').addEventListener('change', applyFilters);
        window.addEventListener('scroll', () => {{
            const sections = document.querySelectorAll('.section');
            let current = '';
            sections.forEach(section => {{
                const sectionTop = section.offsetTop;
                if (window.pageYOffset >= sectionTop - 100) {{ current = section.getAttribute('id'); }}
            }});
            document.querySelectorAll('.nav-item').forEach(item => {{
                item.classList.remove('active');
                if (item.getAttribute('href') === '#' + current) {{ item.classList.add('active'); }}
            }});
        }});
    </script>
</body>
</html>'''

        consolidated_html = html_template.format(
            timestamp=timestamp_display,
            date_display=date_display,
            num_accounts=len(account_ids),
            total_findings=total_findings,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            passed_count=passed_count,
            pass_rate=pass_rate,
            bedrock_total=service_stats['bedrock']['passed'] + service_stats['bedrock']['failed'],
            bedrock_failed=service_stats['bedrock']['failed'],
            bedrock_passed=service_stats['bedrock']['passed'],
            sagemaker_total=service_stats['sagemaker']['passed'] + service_stats['sagemaker']['failed'],
            sagemaker_failed=service_stats['sagemaker']['failed'],
            sagemaker_passed=service_stats['sagemaker']['passed'],
            agentcore_total=service_stats['agentcore']['passed'] + service_stats['agentcore']['failed'],
            agentcore_failed=service_stats['agentcore']['failed'],
            agentcore_passed=service_stats['agentcore']['passed'],
            alerts=alerts_html,
            account_options=account_options,
            all_rows=all_rows,
            bedrock_rows=bedrock_rows,
            sagemaker_rows=sagemaker_rows,
            agentcore_rows=agentcore_rows
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