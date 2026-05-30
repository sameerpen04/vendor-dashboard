import pandas as pd
import requests
import feedparser
import json
from datetime import datetime

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'
# RSS feeds for live security breach monitoring
RSS_FEEDS = ["https://feeds.bleepingcomputer.com/"] 

def get_live_threats():
    """Fetches CISA KEV data."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def get_news_threats(vendor_name):
    """Crawls RSS feeds for news-based breaches."""
    breaches = []
    for url in RSS_FEEDS:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            if vendor_name.lower() in entry.title.lower():
                breaches.append({'dateAdded': entry.published, 'shortDescription': entry.title})
    return breaches

def check_web_status(url):
    try:
        resp = requests.get(url, timeout=5)
        return "Stable" if resp.status_code == 200 else "Degraded"
    except: return "Offline"

def build_final_app():
    df = pd.read_excel(EXCEL_FILE)
    cisa_threats = get_live_threats()
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        
        # Combine CISA + RSS News Crawling
        cisa_hits = [t for t in cisa_threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        news_hits = get_news_threats(vendor_name)
        history = cisa_hits + news_hits
        
        is_breached = len(history) > 0
        web_status = check_web_status(row['Web URL'])
        
        status = "UNSECURED" if is_breached or web_status != "Stable" else "SECURED"
        color = "bg-red-500" if status == "UNSECURED" else "bg-green-500"
        
        nature = f"Alert: {history[0]['shortDescription']} | Source: {'CISA KEV' if cisa_hits else 'Security News'}" if is_breached else "No security breaches or unauthorized disclosures reported. System perimeters are stable."
        
        return pd.Series([status, color, nature, row['Inherent Risk Rating'], "CRITICAL" if is_breached else row['Inherent Risk Rating'], "Investigate" if is_breached else "Monitor", json.dumps(history)])

    df[['24h Status', 'StatusColor', 'Nature of Breach', 'Inherent Risk', 'New Risk Profile', 'Breach Impact', 'History']] = df.apply(analyze_vendor, axis=1)
    
    # ... (HTML rendering remains the same, using 'vendors_json' to populate the modal) ...
