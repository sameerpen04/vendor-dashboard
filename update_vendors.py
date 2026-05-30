import pandas as pd
import requests
import feedparser
import json
import os

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'
RSS_FEEDS = ["https://feeds.bleepingcomputer.com/"]

def get_live_threats():
    """Fetches verified CISA KEV data."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def get_news_threats(vendor_name):
    """Crawls RSS feeds for news-based breaches."""
    breaches = []
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                if vendor_name.lower() in entry.title.lower():
                    breaches.append({'dateAdded': entry.published, 'shortDescription': entry.title})
        except: continue
    return breaches

def build_app():
    if not os.path.exists(EXCEL_FILE):
        print(f"Error: {EXCEL_FILE} not found.")
        return

    df = pd.read_excel(EXCEL_FILE)
    cisa_threats = get_live_threats()
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        # Fetch CISA + News
        cisa_hits = [t for t in cisa_threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        news_hits = get_news_threats(vendor_name)
        history = cisa_hits + news_hits
        
        is_breached = len(history) > 0
        status = "UNSECURED" if is_breached else "SECURED"
        color = "bg-red-500" if is_breached else "bg-green-500"
        
        nature = f"Source ({'CISA' if cisa_hits else 'News'}): {history[0]['shortDescription']}" if is_breached else "Stable - No breaches reported."
        
        return pd.Series([status, color, nature, row['Inherent Risk Rating'], "CRITICAL" if is_breached else row['Inherent Risk Rating'], json.dumps(history)])

    df[['Status', 'Color', 'Nature', 'Inherent Risk', 'New Risk', 'History']] = df.apply(analyze_vendor, axis=1)
    
    vendors_json = df.to_json(orient='records')
    
    # HTML Template
    html = f"""<!DOCTYPE html>
<html><head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-8">
<h1 class="text-2xl font-bold mb-4">CISO TPRM GRC Board</h1>
<table class="w-full bg-white shadow rounded">
    <thead class="bg-gray-200"><tr><th>Vendor</th><th>Status</th><th>Nature</th><th>Inherent</th><th>Drilldown</th></tr></thead>
    <tbody>
        {"".join([f"<tr><td class='p-2 border'>{r['Vendor Name']}</td><td class='p-2 border'><span class='{r['Color']} text-white px-2 py-1 rounded'>{r['Status']}</span></td><td class='p-2 border text-sm'>{r['Nature']}</td><td class='p-2 border'>{r['Inherent Risk']}</td><td class='p-2 border'><button onclick='alert({r['History']})' class='text-blue-600'>History</button></td></tr>" for _, r in df.iterrows()])}
    </tbody>
</table>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"Successfully generated {OUTPUT_FILE}")

if __name__ == "__main__":
    build_app()
