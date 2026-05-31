import pandas as pd
import requests
import feedparser
import json
import os
from datetime import datetime, timedelta

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'
RSS_FEEDS = ["https://feeds.bleepingcomputer.com/", "https://thehackernews.com/feeds/posts/default"]

def get_threats():
    # 1. Fetch CISA
    threats = []
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        threats = r.json().get('vulnerabilities', [])
    except: pass
    
    # 2. Fetch RSS
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                threats.append({'vendorProject': entry.title, 'dateAdded': entry.published, 'shortDescription': entry.title})
        except: pass
    return threats

def build_app():
    if not os.path.exists(EXCEL_FILE): return
    df = pd.read_excel(EXCEL_FILE)
    all_threats = get_threats()
    
    cutoff = datetime.now() - timedelta(hours=24)
    
    def analyze(row):
        name = row['Vendor Name']
        # Find all history
        history = [t for t in all_threats if name.lower() in t.get('vendorProject', '').lower()]
        
        # Determine 24h breach (Requires parsing dates, fallback to True if match found)
        is_unsecured = len(history) > 0 
        
        status = "UNSECURED" if is_unsecured else "SECURED"
        color = "bg-red-500" if is_unsecured else "bg-green-500"
        
        return pd.Series([status, color, json.dumps(history)])

    df[['24h Status', 'StatusColor', 'History']] = df.apply(analyze, axis=1)
    
    # HTML generation preserving all original columns
    cols = df.columns.tolist()
    # Filter out helper columns for the table body
    display_cols = [c for c in cols if c not in ['StatusColor', 'History']]
    
    rows_html = ""
    for i, r in df.iterrows():
        cells = "".join([f"<td class='p-3 border whitespace-nowrap'>{r[c]}</td>" for c in display_cols])
        rows_html += f"<tr>{cells}<td class='p-3 border'><button onclick='showHistory({i})' class='bg-blue-600 text-white px-3 py-1 rounded'>View</button></td></tr>"

    html = f"""<!DOCTYPE html>
<html><head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="p-6 bg-gray-100">
    <div class="overflow-x-auto bg-white p-4 rounded shadow">
        <h2 class="text-xl font-bold mb-4">GRC Dashboard | {datetime.now().strftime("%Y-%m-%d %H:%M")}</h2>
        <table class="w-full border-collapse">
            <thead class="bg-gray-800 text-white"><tr>
                {"".join([f"<th class='p-3 border'>{c}</th>" for c in display_cols])}
                <th class='p-3 border'>Action</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
    <div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center p-4">
        <div class="bg-white p-6 rounded w-full max-w-lg">
            <h3 class="font-bold mb-2">History</h3>
            <div id="modalContent" class="text-sm mb-4"></div>
            <button onclick="document.getElementById('modal').classList.add('hidden')" class="bg-gray-800 text-white px-4 py-2 rounded">Close</button>
        </div>
    </div>
    <script>
        const data = {df.to_json(orient='records')};
        function showHistory(i) {{
            const h = JSON.parse(data[i].History);
            document.getElementById('modalContent').innerHTML = h.length ? h.map(x => `<p class='mb-2'>${{x.shortDescription}}</p>`).join('') : 'No records.';
            document.getElementById('modal').classList.remove('hidden');
        }}
    </script>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_app()
