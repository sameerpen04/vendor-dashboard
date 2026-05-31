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
    """Aggregates CISA and RSS feeds."""
    threats = []
    # CISA Data
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        for v in r.json().get('vulnerabilities', []):
            threats.append({'name': v.get('vendorProject', ''), 'date': v.get('dateAdded', ''), 'desc': v.get('shortDescription', '')})
    except: pass
    # RSS Data
    for url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for e in feed.entries:
                threats.append({'name': e.title, 'date': e.published, 'desc': e.title})
        except: pass
    return threats

def build_app():
    if not os.path.exists(EXCEL_FILE): return
    df = pd.read_excel(EXCEL_FILE)
    all_threats = get_threats()
    now = datetime.now()
    cutoff = now - timedelta(hours=24)

    def analyze(row):
        name = row['Vendor Name']
        # Find all history (RSS + CISA)
        history = [t for t in all_threats if name.lower() in t['name'].lower()]
        
        # 24h Status Check
        recent = [h for h in history if 'date' in h and h['date'] and 
                  (datetime.strptime(h['date'][:10], '%Y-%m-%d') > cutoff if len(h['date']) >= 10 else False)]
        
        is_unsecured = len(recent) > 0
        status = "UNSECURED" if is_unsecured else "SECURED"
        
        # Risk color mapping
        risk = str(row.get('Inherent Risk Rating', 'Medium'))
        risk_color = "bg-red-200" if "High" in risk else ("bg-yellow-200" if "Medium" in risk else "bg-green-200")
        
        return pd.Series([status, risk_color, json.dumps(history)])

    df[['Status', 'RiskColor', 'History']] = df.apply(analyze, axis=1)
    
    # 1. Prepare Columns for Table Header
    all_cols = list(df.columns)
    display_cols = [c for c in all_cols if c not in ['Status', 'RiskColor', 'History']]
    
    # 2. Construct Table Rows Manually to avoid F-string errors
    rows_html = ""
    for i, r in df.iterrows():
        cells = "".join([f"<td class='p-3 border break-words'>{r[c]}</td>" for c in display_cols])
        rows_html += f"""<tr class='text-sm'>
            {cells}
            <td class='p-3 border font-bold {r['RiskColor']}'>{r.get('Inherent Risk Rating', 'N/A')}</td>
            <td class='p-3 border'><span class='{'bg-red-500' if r['Status']=='UNSECURED' else 'bg-green-500'} text-white px-2 py-1 rounded'>{r['Status']}</span></td>
            <td class='p-3 border'><button onclick='showHistory({i})' class='bg-purple-600 text-white px-3 py-1 rounded'>View</button></td>
        </tr>"""

    # 3. Construct Final HTML
    html = f"""<!DOCTYPE html>
<html><head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-6">
    <div class="bg-purple-800 text-white p-6 rounded-t-lg">
        <h1 class="text-2xl font-bold">Vendor Live Breach Tracker</h1>
        <p class="text-sm">Last Update: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    <div class="bg-white p-4 shadow overflow-x-auto">
        <table class="w-full border-collapse table-auto">
            <thead class="bg-gray-200"><tr>
                {"".join([f"<th class='p-3 border text-left'>{c}</th>" for c in display_cols])}
                <th class='p-3 border'>Risk</th><th class='p-3 border'>Status</th><th class='p-3 border'>Action</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
    <div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center p-4">
        <div class="bg-white p-6 rounded w-full max-w-lg max-h-[80vh] overflow-y-auto">
            <h3 class="font-bold mb-4">Breach History & Timeline</h3>
            <div id="modalContent" class="text-sm"></div>
            <button onclick="document.getElementById('modal').classList.add('hidden')" class="mt-4 bg-gray-800 text-white px-4 py-2 rounded">Close</button>
        </div>
    </div>
    <script>
        const data = {df.to_json(orient='records')};
        function showHistory(i) {{
            const h = JSON.parse(data[i].History);
            document.getElementById('modalContent').innerHTML = h.length ? h.map(x => `<div class='mb-3 border-b pb-2'><b>${{x.date}}</b><br>${{x.desc}}</div>`).join('') : 'No recorded history found.';
            document.getElementById('modal').classList.remove('hidden');
        }}
    </script>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_app()
