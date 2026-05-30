import pandas as pd
import requests
import json
from datetime import datetime
import pytz

# --- CORE CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_threat_intel():
    """Fetches CISA KEV Threat Intel."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=5)
        return r.json().get('vulnerabilities', [])
    except: return []

def build_final_app():
    # 1. Load Data
    df = pd.read_excel(EXCEL_FILE)
    intel = get_threat_intel()
    risk_stats = df['Inherent Risk Rating'].value_counts().to_dict()
    
    # 2. Convert Data for JS
    vendors_json = df.to_json(orient='records')
    intel_json = json.dumps(intel[:15])

    # 3. HTML Construction
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>.tab-content {{ display: none; }}.active {{ display: block; }}</style>
    <script>
        const vendors = {vendors_json};
        const intel = {intel_json};
        function openTab(id) {{
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(id).classList.add('active');
        }}
        function searchTable() {{
            const q = document.getElementById('search').value.toLowerCase();
            document.querySelectorAll('#regBody tr').forEach(tr => {{
                tr.style.display = tr.innerText.toLowerCase().includes(q) ? '' : 'none';
            }});
        }}
    </script>
</head>
<body class="bg-gray-50 text-gray-900">
    <nav class="bg-slate-900 p-6 text-white shadow-xl">
        <h1 class="text-3xl font-bold">CISO TPRM GRC BOARD</h1>
        <p class="text-xs opacity-75">Updated: {datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M')}</p>
    </nav>

    <div class="p-8">
        <div class="flex gap-4 mb-6">
            <button onclick="openTab('d')" class="bg-indigo-700 text-white px-6 py-2 rounded shadow">Dashboard</button>
            <button onclick="openTab('r')" class="bg-indigo-700 text-white px-6 py-2 rounded shadow">Register</button>
            <button onclick="openTab('i')" class="bg-indigo-700 text-white px-6 py-2 rounded shadow">Live Intel</button>
        </div>

        <div id="d" class="tab-content active bg-white p-6 rounded shadow">
            <h2 class="text-2xl font-bold mb-4">Risk Distribution</h2>
            <div class="grid grid-cols-4 gap-4">
                {"".join([f"<div class='border p-4 rounded bg-gray-50'><strong>{k}</strong><br><span class='text-2xl'>{v}</span></div>" for k, v in risk_stats.items()])}
            </div>
        </div>

        <div id="r" class="tab-content bg-white p-6 rounded shadow">
            <input type="text" id="search" onkeyup="searchTable()" placeholder="Search vendors..." class="w-full border p-2 mb-4 rounded">
            <table class="w-full text-left">
                <thead class="bg-gray-100"><tr><th class="p-3">Vendor</th><th class="p-3">Risk</th><th class="p-3">Compliance</th></tr></thead>
                <tbody id="regBody">
                    {"".join([f"<tr class='border-b'><td class='p-3'>{r['Vendor Name']}</td><td class='p-3'>{r['Inherent Risk Rating']}</td><td class='p-3'><a href='{r['Security / Trust Center URL']}' target='_blank' class='text-blue-600'>View</a></td></tr>" for _, r in df.iterrows()])}
                </tbody>
            </table>
        </div>

        <div id="i" class="tab-content bg-white p-6 rounded shadow">
            <h2 class="text-xl font-bold mb-4">Live CISA Threat Feed</h2>
            <div id="intelBody">{"".join([f"<div class='p-3 border-b'><strong class='text-red-600'>{i['cveID']}</strong> - {i['shortDescription']}</div>" for i in intel])}</div>
        </div>
    </div>
</body>
</html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_final_app()
