import pandas as pd
import requests
import json
import os
from datetime import datetime

# --- CONFIG ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_live_threats():
    try:
        r = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        return r.json().get('vulnerabilities', [])
    except: return []

def build_app():
    if not os.path.exists(EXCEL_FILE): return
    df = pd.read_excel(EXCEL_FILE)
    cisa_threats = get_live_threats()
    
    # Store all original columns
    cols = df.columns.tolist()
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        history = [t for t in cisa_threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        
        is_breached = len(history) > 0
        status = "UNSECURED" if is_breached else "SECURED"
        color = "bg-red-500" if is_breached else "bg-green-500"
        
        nature = f"Source (CISA): {history[0]['shortDescription']}" if is_breached else "System perimeters stable."
        breach_date = history[0].get('dateAdded', 'N/A') if is_breached else "N/A"
        
        return pd.Series([status, color, nature, breach_date, "CRITICAL" if is_breached else row['Inherent Risk Rating'], json.dumps(history)])

    df[['24h Status', 'StatusColor', 'Nature of Breach', 'Breach Date/Time', 'New Risk Profile', 'History']] = df.apply(analyze_vendor, axis=1)
    
    # Safely convert to JSON for JS
    vendors_json = df.to_json(orient='records')
    update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Construct rows outside of complex f-strings
    rows_html = ""
    for i, r in df.iterrows():
        cols_html = "".join([f"<td class='p-3 border'>{r[c]}</td>" for c in cols])
        rows_html += f"""<tr class='border-b hover:bg-gray-50'>
            {cols_html}
            <td class='p-3 border'><span class='{r['StatusColor']} text-white px-3 py-1 rounded-full text-xs font-bold'>{r['24h Status']}</span></td>
            <td class='p-3 border text-sm'>{r['Nature of Breach']}</td>
            <td class='p-3 border text-sm'>{r['Breach Date/Time']}</td>
            <td class='p-3 border text-sm font-semibold'>{r['New Risk Profile']}</td>
            <td class='p-3 border'><button onclick='showHistory({i})' class='bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700'>View</button></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><script src="https://cdn.tailwindcss.com"></script>
<script>
    const vendors = {vendors_json};
    function showHistory(idx) {{
        const h = vendors[idx].History;
        const data = typeof h === 'string' ? JSON.parse(h) : h;
        document.getElementById('modalBody').innerHTML = data.length > 0 ? 
            data.map(i => `<li class='mb-2 p-2 bg-gray-100'><strong>${{i.dateAdded}}</strong>: ${{i.shortDescription}}</li>`).join('') : '<li>No historical breaches found.</li>';
        document.getElementById('modal').classList.remove('hidden');
    }}
</script></head>
<body class="bg-gray-50 p-8">
<div class="max-w-7xl mx-auto">
    <h1 class="text-3xl font-bold">CISO TPRM GRC BOARD</h1>
    <p class="text-sm mb-6">Last Updated: {update_time}</p>
    <div class="bg-white p-6 rounded shadow overflow-x-auto">
        <table class="w-full border-collapse">
            <thead class="bg-gray-800 text-white">
                <tr>{"".join([f"<th class='p-3 border'>{c}</th>" for c in cols + ['24h Status', 'Nature', 'Date', 'New Risk', 'Action']])}</tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</div>
<div id="modal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center p-4">
    <div class="bg-white p-8 rounded shadow w-full max-w-lg">
        <h2 class='font-bold mb-4'>Breach History</h2>
        <div id="modalBody" class='text-sm mb-4'></div>
        <button onclick="document.getElementById('modal').classList.add('hidden')" class='bg-gray-800 text-white px-4 py-2 rounded'>Close</button>
    </div>
</div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)
    print("Dashboard Updated.")

if __name__ == "__main__": build_app()
