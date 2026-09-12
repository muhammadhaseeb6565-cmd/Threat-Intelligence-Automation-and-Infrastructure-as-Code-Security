import argparse
import json
import yaml
import os
from datetime import datetime, timedelta

def load_config():
    config_file = "ioc_config.yaml"
    if not os.path.exists(config_file):
        return {}
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def load_db(path):
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def save_db(db, path):
    with open(path, 'w') as f:
        json.dump(db, f, indent=4)

def determine_type(indicator):
    if len(indicator) in [32, 40, 64]:
        return "hash"
    elif any(c.isalpha() for c in indicator):
        return "domain"
    else:
        return "ip"

def add_ioc(db, indicator, risk_score, source):
    now = datetime.now().isoformat()
    if indicator in db:
        # Update existing
        db[indicator]['last_seen'] = now
        db[indicator]['confidence'] = max(db[indicator]['confidence'], risk_score)
        if source not in db[indicator]['sources']:
            db[indicator]['sources'].append(source)
            # Source diversity boosts confidence
            db[indicator]['confidence'] = min(100, db[indicator]['confidence'] + 5)
        print(f"[*] Updated {indicator} - Confidence: {db[indicator]['confidence']}")
    else:
        # Add new
        db[indicator] = {
            "type": determine_type(indicator),
            "first_seen": now,
            "last_seen": now,
            "confidence": risk_score,
            "sources": [source],
            "status": "active"
        }
        print(f"[*] Added {indicator}")

def expire_check(db, config):
    now = datetime.now()
    exp_config = config.get('expiration', {'ip': 14, 'domain': 30, 'hash': 365})
    expired_count = 0
    for ind, data in db.items():
        if data['status'] == 'active':
            last_seen = datetime.fromisoformat(data['last_seen'])
            days_valid = exp_config.get(data['type'], 30)
            if now - last_seen > timedelta(days=days_valid):
                data['status'] = 'expired'
                expired_count += 1
    print(f"[*] Expiration check complete. Expired {expired_count} stale IOCs.")
    return db

def export_blocklist(db, config):
    path = config.get('siem_export_path', 'blocklist.txt')
    threshold = config.get('confidence_thresholds', {}).get('blocklist', 70)
    count = 0
    with open(path, 'w') as f:
        f.write("# SIEM Blocklist Export\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        for ind, data in db.items():
            if data['status'] == 'active' and data['confidence'] >= threshold:
                f.write(f"{ind}\n")
                count += 1
    print(f"[*] Exported {count} IOCs to {path}")

def generate_report(db, config):
    path = config.get('report_export_path', 'weekly_report.html')
    active_count = sum(1 for d in db.values() if d['status'] == 'active')
    expired_count = sum(1 for d in db.values() if d['status'] == 'expired')
    high_conf = sum(1 for d in db.values() if d['status'] == 'active' and d['confidence'] >= 70)
    
    html = f"""
    <html>
    <head><title>Weekly IOC Report</title></head>
    <body>
        <h1>Weekly Threat Intelligence Report</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <h2>Metrics</h2>
        <ul>
            <li>Total Active IOCs: {active_count}</li>
            <li>Total Expired IOCs: {expired_count}</li>
            <li>High Confidence (Blocklist) IOCs: {high_conf}</li>
        </ul>
        <h2>Recent High Confidence IOCs</h2>
        <table border="1">
            <tr><th>Indicator</th><th>Type</th><th>Confidence</th><th>Last Seen</th></tr>
    """
    
    for ind, data in db.items():
        if data['status'] == 'active' and data['confidence'] >= 70:
            html += f"<tr><td>{ind}</td><td>{data['type']}</td><td>{data['confidence']}</td><td>{data['last_seen']}</td></tr>"
            
    html += """
        </table>
    </body>
    </html>
    """
    with open(path, 'w') as f:
        f.write(html)
    print(f"[*] Report generated at {path}")

def main():
    parser = argparse.ArgumentParser(description="IOC Manager & Automation")
    parser.add_argument("--add-file", help="Import new IOCs from a JSON/CSV file")
    parser.add_argument("--update-all", action="store_true", help="Re-enrich all active IOCs")
    parser.add_argument("--expire-check", action="store_true", help="Remove stale IOCs")
    parser.add_argument("--export-blocklist", action="store_true", help="Generate SIEM import")
    parser.add_argument("--generate-report", action="store_true", help="Generate weekly report")
    
    args = parser.parse_args()
    config = load_config()
    db_path = config.get('database_path', 'ioc_database.json')
    db = load_db(db_path)

    if args.add_file:
        print(f"[*] Loading file: {args.add_file}")
        # Dummy implementation for importing file, realistically would parse CSV
        add_ioc(db, "1.1.1.1", 85, "OSINT")
        add_ioc(db, "evil.com", 90, "VirusTotal")
        add_ioc(db, "safe.com", 10, "OSINT")

    if args.expire_check:
        db = expire_check(db, config)
        
    if args.update_all:
        print("[*] Re-enriching all IOCs (stub)...")

    if args.export_blocklist:
        export_blocklist(db, config)
        
    if args.generate_report:
        generate_report(db, config)
        
    # Always save db state
    save_db(db, db_path)

if __name__ == "__main__":
    main()
