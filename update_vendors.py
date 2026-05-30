import pandas as pd
import requests
import json
import os
from datetime import datetime

# Attempt to import feedparser; if missing, define a fallback so the app still runs
try:
    import feedparser
    HAS_FEEDPARSER = True
except ImportError:
    HAS_FEEDPARSER = False

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'
RSS_FEEDS = ["https://feeds.bleepingcomputer.com/"]

def get_live_threats():
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def get_news_threats(vendor_name):
    if not HAS_FEEDPARSER: return []
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
    if not os.path.exists(EXCEL_FILE): return
    df = pd.read_excel(EXCEL_FILE)
    cisa_threats = get_live_threats()
    original_cols = df.columns.tolist()
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        history = [t for t in cisa_threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        history += get_news_threats(vendor_name)
        
        is_breached = len(history) > 0
        status = "UNSECURED" if is_breached else "SECURED"
        color = "bg-red-500" if is_breached else "bg-green-500"
        
        nature = f"Source ({'CISA/News'}): {history[0]['shortDescription']}" if is_breached else "No breaches reported. System stable."
        breach_date = history[0].get('dateAdded', 'N/A') if is_breached else "N/A"
        
        return pd.Series([status, color, nature, breach_date, "CRITICAL" if is_breached else row.get('Inherent Risk Rating', 'N/A'), json.dumps(history)])

    df[['24h Status', 'StatusColor', 'Nature of Breach', 'Breach Date/Time', 'New Risk Profile', 'History']] = df.apply(analyze_vendor, axis=1)
    
    vendors_json = df.to_json(orient='records')
    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    headers = original_cols + ['24h Status', 'Nature of Breach', 'Breach Date/Time', 'New Risk Profile', 'Action']
    header_html = "".join([f"<th class='p-3 border'>{col}</th>" for col in headers])
    rows_html = "".join([f"""<tr class='border-b hover:bg-gray-50'>
        {''.join([f"<td class='p-3 border'>{r[col]}</td>" for col in original_cols])}
        <td class='p-3 border'><span class='{r['StatusColor']} text-white px-3 py-1 rounded-full text-xs font-bold'>{r['24h Status']}</span></td>
        <td class='p-3 border text-sm'>{r['Nature of Breach']}</td>
        <td class='p-3 border text-sm'>{r['Breach Date/Time']}</td>
        <td class='p-3 border text-sm font-semibold'>{r['New Risk Profile']}</td>
        <td class='p-3 border'><button onclick='showHistory({i})' class='bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition'>History</button></td>
    </tr>""" for i, r in df.iterrows()])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><script src="https://cdn.tailwindcss.com"></script>
<script>
    const vendors = {vendors_json};
    function showHistory(idx) {{
        const h = JSON.parse(vendors[idx].History);
        let list = h.length > 0 ? h.map(i => `<li class='mb-2 p-2 bg-gray-100 rounded'><strong>${{i.dateAdded}}</strong>: ${{i.shortDescription}}</li>`).join('') : '<li class="p-2">No historical breaches found.</li>';
        document.getElementById('modalBody').innerHTML = `<ul>${{list}}</ul>`;
        document.getElementById('modal').classList.remove('hidden');
    }}
</script></head>
<body class="bg-gray-50 p-8">
<div class="max-w-7xl mx-auto">
    <h1 class="text-4xl font-extrabold text-gray-900">CISO TPRM GRC Board</h1>
    <p class="text-sm text-gray-600 mb-6">Last Updated: {update_time}</p>
    <div class="bg-white p-6 rounded-lg shadow-lg overflow-x-auto">
        <table class="w-full text-left border-collapse">
            <thead class="bg-gray-800 text-white">{header_html}</thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</div>
<div id="modal" class="hidden fixed inset-0 bg-black/60 flex items-center justify-center p-4">
    <div class="bg-white p-8 rounded-xl shadow-2xl w-full max-w-2xl">
        <h2 class='text-2xl font-bold mb-4'>Breach History</h2>
        <div id="modalBody" class='text-sm mb-6'></div>
        <button onclick="document.getElementById('modal').classList.add('hidden')" class='bg-gray-800 text-white px-6 py-2 rounded-lg'>Close</button>
    </div>
</div></body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_app()
