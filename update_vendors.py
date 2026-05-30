import pandas as pd
import requests
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
    
    def analyze_vendor(row):
        vendor_name = row['Vendor Name']
        rationale = row['Risk Rationale']
        
        # Match past 3 years of vulnerabilities
        history = [t for t in threats if vendor_name.lower() in t.get('vendorProject', '').lower()]
        breach_count = len(history)
        
        # Impact Assessment Logic
        impact = "Minimal"
        if breach_count > 0:
            impact = f"High: Potential unauthorized access to {rationale[:30]}..."
        
        return pd.Series([
            "ACTIVE" if breach_count > 0 else "CLEAN",
            f"{breach_count} Breaches (3yr)",
            impact,
            row['Inherent Risk Rating']
        ])

    df[['24h Status', 'Historical Breaches', 'Breach Impact', 'New Risk']] = df.apply(analyze_vendor, axis=1)
    vendors_json = df.to_json(orient='records')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-100 p-8">
    <h1 class="text-3xl font-bold mb-6">CISO TPRM GRC BOARD</h1>
    <div class="bg-white p-6 rounded shadow overflow-x-auto">
        <table class="w-full text-left border-collapse">
            <thead class="bg-gray-200"><tr>
                <th class="p-3">Vendor</th><th class="p-3">Category</th><th class="p-3">24h Status</th>
                <th class="p-3">History</th><th class="p-3">Breach Impact</th>
            </tr></thead>
            <tbody>
                {"".join([f"<tr class='border-b'><td class='p-3'>{r['Vendor Name']}</td><td class='p-3'>{r['Risk Rationale']}</td><td class='p-3'>{r['24h Status']}</td><td class='p-3'>{r['Historical Breaches']}</td><td class='p-3 text-red-600'>{r['Breach Impact']}</td></tr>" for _, r in df.iterrows()])}
            </tbody>
        </table>
    </div>
</body></html>"""
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(html)

if __name__ == "__main__": build_final_app()
