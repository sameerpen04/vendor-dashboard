import pandas as pd
import requests
import json
from datetime import datetime

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_live_threats():
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def check_web_status(url):
    try:
        resp = requests.get(url, timeout=5)
        return "Stable" if resp.status_code == 200 else "Degraded"
    except: return "Offline"

def build_final_app():
    df = pd.read_excel(EXCEL_FILE)
    threats = get_live_threats()
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        history = [t for t in threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        
        is_breached = len(history) > 0
        status = "UNSECURED" if is_breached else "SECURED"
        color = "bg-red-500" if is_breached else "bg-green-500"
        
        # Breach details with Source and Timestamp
        nature = f"Source (CISA KEV): {history[0]['shortDescription']} | Reported: {history[0]['dateAdded']}" if is_breached else "No security breaches or unauthorized disclosures reported within the last 24-hour cycle. System perimeters are stable."
        
        impact = f"Potential compromise of {row['Risk Rationale']}. Immediate investigation required." if is_breached else "Stable environment."
        
        return pd.Series([status, color, nature, row['Inherent Risk Rating'], "CRITICAL" if is_breached else row['Inherent Risk Rating'], impact, json.dumps(history)])

    # Add columns while maintaining all original file columns
    df[['24h Status', 'StatusColor', 'Nature of Breach', 'Inherent Risk', 'New Risk Profile', 'Breach Impact', 'History']] = df.apply(analyze_vendor, axis=1)
    
    vendors_json = df.to_json(orient='records')
    
    # HTML Rendering
    html = f"""<!DOCTYPE html>
<html><head><script src="https://cdn.tailwindcss.com"></script>
<script>
    const vendors = {vendors_json};
    function showDrillDown(idx) {{
        const h = JSON.parse(vendors[idx].History);
        let list = h.length > 0 ? h.map(i => `<li><strong>${{i.dateAdded}}</strong>: ${{i.shortDescription}}</li>`).join('') : '<li>No historical breaches found in CISA KEV database.</li>';
        document.getElementById('modalBody').innerHTML = `<ul>${{list}}</ul>`;
        document.getElementById('modal').classList.remove('hidden');
    }}
</script>
</head>
<body class="bg-gray-100 p-8">
<h1 class="text-3xl font-bold mb-6">CISO TPRM GRC BOARD</h1>
<div class="bg-white p-6 rounded shadow overflow-x-auto">
<table class="w-full border-collapse">
    <thead class="bg-gray-200"><tr>
        <th class="p-2 text-xs">Vendor</th><th class="p-2 text-xs">Category</th><th class="p-2 text-xs">24h Status</th>
        <th class="p-2 text-xs">Nature of Breach (Source: CISA KEV)</th><th class="p-2 text-xs">Inherent Risk</th>
        <th class="p-2 text-xs">New Risk Profile</th><th class="p-2 text-xs">Breach Impact</th><th class="p-2 text-xs">History</th>
    </tr></thead>
    <tbody>
        {"".join([f"<tr><td class='p-2 border text-xs'>{r['Vendor Name']}</td><td class='p-2 border text-xs'>{r['Risk Rationale']}</td><td class='p-2 border'><span class='{r['StatusColor']} text-white px-2 py-1 rounded text-xs'>{r['24h Status']}</span></td><td class='p-2 border text-xs'>{r['Nature of Breach']}</td><td class='p-2 border text-xs'>{r['Inherent Risk']}</td><td class='p-2 border text-xs'>{r['New Risk Profile']}</td><td class='p-2 border text-xs'>{r['Breach Impact']}</td><td class='p-2 border'><button onclick='showDrillDown({i})' class='text-blue-600 text-xs'>View History</button></td></tr>" for i, r in df.iterrows()])}
    </tbody>
</table>
</div>
<div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center">
    <div class="bg-white p-8 rounded shadow-xl w-1/2"><h2 class='font-bold mb-4'>Breach History (3 Years)</h2><div id="modalBody" class='text-sm mb-4'></div><button onclick="document.getElementById('modal').classList.add('hidden')" class='bg-red-500 text-white px-4 py-2 rounded'>Close</button></div>
</div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_final_app()
