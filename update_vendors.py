import pandas as pd
import requests
import json
from datetime import datetime
import pytz

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_live_threats():
    """Fetches real-time CISA KEV data to cross-reference with your vendors."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def build_final_app():
    df = pd.read_excel(EXCEL_FILE)
    threats = get_live_threats()
    
    # Pre-calculate Impact
    # Cross-reference threat vendors (simplified match)
    df['Recent Breach'] = df['Vendor Name'].apply(lambda x: next((t['cveID'] for t in threats if x.lower() in t.get('vendorProject', '').lower()), "None Detected"))
    
    # Build JS Data for Drill-Down
    vendors_json = df.to_json(orient='records')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        const vendors = {vendors_json};
        function openDrill(idx) {{
            const v = vendors[idx];
            document.getElementById('mBody').innerHTML = `
                <p><strong>URL:</strong> ${{v['Web URL']}}</p>
                <p><strong>Scope/Category:</strong> ${{v['Risk Rationale']}}</p>
                <p><strong>Trust Center:</strong> ${{v['Security / Trust Center URL']}}</p>
                <p class='text-red-600 font-bold'>Breach Found: ${{v['Recent Breach']}}</p>`;
            document.getElementById('modal').classList.remove('hidden');
        }}
    </script>
</head>
<body class="bg-gray-100 p-8">
    <h1 class="text-3xl font-bold mb-6">CISO TPRM GRC BOARD</h1>
    <div class="bg-white p-6 rounded shadow mb-6">
        <h2 class="text-xl font-bold mb-4">Risk Register (Full Data)</h2>
        <input type="text" onkeyup="this.nextElementSibling.querySelectorAll('tr').forEach(tr => tr.style.display = tr.innerText.toLowerCase().includes(this.value) ? '' : 'none')" placeholder="Search all columns..." class="w-full border p-2 mb-4">
        <table class="w-full text-left border-collapse">
            <thead class="bg-gray-200"><tr><th class="p-3">Vendor</th><th class="p-3">Category</th><th class="p-3">Risk</th><th class="p-3">Breach Status</th><th class="p-3">Action</th></tr></thead>
            <tbody id="regBody">
                {"".join([f"<tr class='border-b hover:bg-gray-50'><td class='p-3'>{r['Vendor Name']}</td><td class='p-3'>{r['Risk Rationale']}</td><td class='p-3'>{r['Inherent Risk Rating']}</td><td class='p-3 font-bold text-red-600'>{r['Recent Breach']}</td><td class='p-3'><button onclick='openDrill({i})' class='text-blue-600 underline'>Drill Down</button></td></tr>" for i, r in df.iterrows()])}
            </tbody>
        </table>
    </div>
    
    <div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center">
        <div class="bg-white p-8 rounded w-1/2">
            <h2 class="text-2xl font-bold mb-4">Vendor Details</h2>
            <div id="mBody"></div>
            <button onclick="document.getElementById('modal').classList.add('hidden')" class="mt-4 bg-red-600 text-white px-4 py-2 rounded">Close</button>
        </div>
    </div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_final_app()
