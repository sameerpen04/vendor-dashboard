import pandas as pd
import requests
import json
import os
from datetime import datetime, timedelta

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
    
    now = datetime.now()
    cutoff = now - timedelta(hours=24)
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        history = [t for t in cisa_threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        
        recent = [h for h in history if datetime.strptime(h.get('dateAdded', '2000-01-01'), '%Y-%m-%d') > cutoff]
        is_unsecured = len(recent) > 0
        
        status = "UNSECURED" if is_unsecured else "SECURED"
        color = "bg-red-500" if is_unsecured else "bg-green-500"
        
        nature = f"Active Alert: {recent[0]['shortDescription']}" if is_unsecured else "System perimeters stable."
        last_date = recent[0].get('dateAdded') if is_unsecured else (history[0].get('dateAdded') if history else "N/A")
        
        return pd.Series([status, color, nature, last_date, json.dumps(history)])

    df[['24h Status', 'StatusColor', 'Nature of Breach', 'Last Reported', 'History']] = df.apply(analyze_vendor, axis=1)
    
    # Generate Table Rows safely outside the f-string
    rows_html = ""
    for _, r in df.iterrows():
        # Clean data for alert to avoid JS syntax errors
        history_str = str(r['History']).replace('"', "'")
        row_cols = "".join([f"<td class='p-2 border'>{r[col]}</td>" for col in df.columns if col not in ['StatusColor', 'History']])
        rows_html += f"<tr>{row_cols}<td class='p-2 border'><button onclick=\"alert('{history_str}')\" class='text-blue-500'>View</button></td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-4">
<div class="max-w-[95%] mx-auto">
    <h1 class="text-2xl font-bold">CISO TPRM GRC BOARD</h1>
    <p class="text-xs mb-4">Last Sync: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | <a href="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" class="text-blue-600 underline">Verify Data Source</a></p>
    <div class="bg-white p-4 rounded shadow overflow-x-auto">
        <table class="w-full text-sm border-collapse">
            <thead class="bg-gray-800 text-white"><tr>
                {"".join([f"<th class='p-2 border'>{col}</th>" for col in df.columns if col not in ['StatusColor', 'History']])}
                <th class='p-2 border'>Action</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_app()
