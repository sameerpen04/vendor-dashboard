import pandas as pd
import requests
import json
from datetime import datetime
import pytz

# --- CORE CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_live_threats():
    """Fetches CISA KEV data."""
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def build_final_app():
    df = pd.read_excel(EXCEL_FILE)
    threats = get_live_threats()
    
    # Logic: Cross-reference & Update columns
    def get_breach_data(vendor_name):
        match = next((t for t in threats if vendor_name.lower() in t.get('vendorProject', '').lower()), None)
        if match:
            return "ACTIVE", match.get('shortDescription', 'Unknown Breach'), "CRITICAL"
        return "CLEAN", "None", df.loc[df['Vendor Name'] == vendor_name, 'Inherent Risk Rating'].values[0]

    # Apply new columns
    df[['24h Status', 'Nature of Breach', 'New Risk Framework Profile']] = df.apply(
        lambda row: pd.Series(get_breach_data(row['Vendor Name'])), axis=1
    )
    
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
                <p><strong>Vendor:</strong> ${{v['Vendor Name']}}</p>
                <p><strong>Breach Nature:</strong> ${{v['Nature of Breach']}}</p>
                <p><strong>New Risk Profile:</strong> ${{v['New Risk Framework Profile']}}</p>`;
            document.getElementById('modal').classList.remove('hidden');
        }}
    </script>
</head>
<body class="bg-gray-100 p-8">
    <h1 class="text-3xl font-bold mb-6">CISO TPRM GRC BOARD</h1>
    <div class="bg-white p-6 rounded shadow">
        <table class="w-full text-left border-collapse">
            <thead class="bg-gray-200"><tr>
                <th class="p-3">Vendor</th>
                <th class="p-3">24h Status</th>
                <th class="p-3">Nature of Breach</th>
                <th class="p-3">New Risk Profile</th>
                <th class="p-3">Action</th>
            </tr></thead>
            <tbody id="regBody">
                {"".join([f"<tr class='border-b'><td class='p-3'>{r['Vendor Name']}</td><td class='p-3'>{r['24h Status']}</td><td class='p-3'>{r['Nature of Breach']}</td><td class='p-3'>{r['New Risk Framework Profile']}</td><td class='p-3'><button onclick='openDrill({i})' class='text-blue-600'>Details</button></td></tr>" for i, r in df.iterrows()])}
            </tbody>
        </table>
    </div>
    <div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center">
        <div class="bg-white p-8 rounded w-1/2">
            <h2 class="text-2xl font-bold mb-4">Deep Dive</h2>
            <div id="mBody"></div>
            <button onclick="document.getElementById('modal').classList.add('hidden')" class="mt-4 bg-red-600 text-white px-4 py-2 rounded">Close</button>
        </div>
    </div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_final_app()
