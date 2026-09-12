import argparse
import yaml
import json
import csv
import time
import requests
import os
from datetime import datetime, timedelta

CONFIG_FILE = "config.yaml"
CACHE_FILE = "cache.json"
CACHE_TTL_HOURS = 24

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: {CONFIG_FILE} not found.")
        exit(1)
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=4)

def check_cache(indicator, cache):
    if indicator in cache:
        entry = cache[indicator]
        timestamp = datetime.fromisoformat(entry['timestamp'])
        if datetime.now() - timestamp < timedelta(hours=CACHE_TTL_HOURS):
            return entry['data']
    return None

def query_virustotal(indicator, config):
    api_key = config.get('virustotal', {}).get('api_key')
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY":
        return {"error": "Missing API Key"}
    
    # Simple logic for IP vs Domain vs Hash
    if len(indicator) in [32, 40, 64]:
        type_path = "files"
    elif any(c.isalpha() for c in indicator):
        type_path = "domains"
    else:
        type_path = "ip_addresses"

    url = f"https://www.virustotal.com/api/v3/{type_path}/{indicator}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {"malicious": stats.get('malicious', 0), "total": sum(stats.values())}
        elif resp.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_abuseipdb(indicator, config):
    api_key = config.get('abuseipdb', {}).get('api_key')
    if not api_key or api_key == "YOUR_ABUSEIPDB_API_KEY":
        return {"error": "Missing API Key"}
    
    # AbuseIPDB is for IPs only
    if any(c.isalpha() for c in indicator):
        return {"error": "Not an IP"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": "90"}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {"abuseConfidenceScore": data.get('abuseConfidenceScore', 0)}
        elif resp.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_otx(indicator, config):
    api_key = config.get('otx', {}).get('api_key')
    if not api_key or api_key == "YOUR_ALIENVAULT_OTX_API_KEY":
        return {"error": "Missing API Key"}

    if len(indicator) in [32, 40, 64]:
        type_path = "file"
    elif any(c.isalpha() for c in indicator):
        type_path = "domain"
    else:
        type_path = "IPv4"

    url = f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {"pulse_count": data.get('pulse_info', {}).get('count', 0)}
        elif resp.status_code == 429:
            return {"error": "Rate limited"}
        else:
            return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def calculate_risk(vt_data, abuse_data, otx_data):
    score = 0
    # VirusTotal contribution (up to 50)
    if not vt_data.get('error'):
        malicious = vt_data.get('malicious', 0)
        if malicious > 0:
            score += min(50, malicious * 10)
            
    # AbuseIPDB contribution (up to 30)
    if not abuse_data.get('error'):
        abuse_score = abuse_data.get('abuseConfidenceScore', 0)
        score += (abuse_score / 100) * 30
        
    # OTX contribution (up to 20)
    if not otx_data.get('error'):
        pulses = otx_data.get('pulse_count', 0)
        if pulses > 0:
            score += min(20, pulses * 5)
            
    return min(100, int(score))

def enrich_indicator(indicator, config, cache):
    cached_data = check_cache(indicator, cache)
    if cached_data:
        print(f"[*] Cache hit for {indicator}")
        return cached_data

    print(f"[*] Querying external sources for {indicator}...")
    # Sleep to respect basic rate limits (e.g., VT free tier allows 4/min)
    time.sleep(15) 
    
    vt_data = query_virustotal(indicator, config)
    abuse_data = query_abuseipdb(indicator, config)
    otx_data = query_otx(indicator, config)

    risk_score = calculate_risk(vt_data, abuse_data, otx_data)

    result = {
        "indicator": indicator,
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "otx": otx_data,
        "risk_score": risk_score
    }

    cache[indicator] = {
        "timestamp": datetime.now().isoformat(),
        "data": result
    }
    save_cache(cache)
    return result

def main():
    parser = argparse.ArgumentParser(description="TI Enrichment Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--indicator", help="Single indicator to enrich (IP, Domain, Hash)")
    group.add_argument("--input-file", help="CSV file containing indicators")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format")
    
    args = parser.parse_args()
    config = load_config()
    cache = load_cache()

    indicators = []
    if args.indicator:
        indicators.append(args.indicator)
    elif args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'indicator' in row:
                        indicators.append(row['indicator'])
        except Exception as e:
            print(f"Error reading file: {e}")
            exit(1)

    results = []
    for ind in indicators:
        res = enrich_indicator(ind, config, cache)
        results.append(res)

    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        with open('enrichment_results.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["indicator", "risk_score", "virustotal", "abuseipdb", "otx"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "indicator": r['indicator'],
                    "risk_score": r['risk_score'],
                    "virustotal": json.dumps(r['virustotal']),
                    "abuseipdb": json.dumps(r['abuseipdb']),
                    "otx": json.dumps(r['otx'])
                })
        print("[*] Results saved to enrichment_results.csv")
    else:
        print("\n--- Enrichment Results ---")
        print(f"{'Indicator':<25} | {'Risk Score':<10} | {'VT':<20} | {'AbuseIPDB':<20} | {'OTX':<20}")
        print("-" * 105)
        for r in results:
            vt = r['virustotal'].get('malicious', 'Err') if not r['virustotal'].get('error') else r['virustotal'].get('error')
            ab = r['abuseipdb'].get('abuseConfidenceScore', 'Err') if not r['abuseipdb'].get('error') else r['abuseipdb'].get('error')
            otx = r['otx'].get('pulse_count', 'Err') if not r['otx'].get('error') else r['otx'].get('error')
            print(f"{r['indicator']:<25} | {r['risk_score']:<10} | {str(vt):<20} | {str(ab):<20} | {str(otx):<20}")

if __name__ == "__main__":
    main()
