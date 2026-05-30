import pandas as pd
import requests
import json
from datetime import datetime
import pytz

# --- CORE SETTINGS ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def get_risk_style(risk):
    styles = {
        'Critical': 'bg-red-600 text-white', 
        'High': 'bg-orange-500 text-white', 
        'Medium': 'bg-yellow-400 text-black', 
        'Low': 'bg-green-500 text-white'
    }
    return styles.get(risk, 'bg-gray-400 text-white')

def build_dashboard():
    # 1. Load Data
    df = pd.read_excel(EXCEL_FILE)
    risk_counts = df['Inherent Risk Rating'].value_counts().to_dict()
    
    # 2. Build Table Rows (Tabs 2 & 3)
    register_rows = ""
    for _, row in df.iterrows():
        name = row.get('Vendor Name', 'N/A')
        risk = row.get('Inherent Risk Rating', 'N/A')
        trust = row.get('Security / Trust Center URL', 'N/A')
        trust_html = f'<a href="{trust}" target="_blank" class="text-indigo-600 underline">Link</a>' if trust != 'N/A' else "N/A"
        
        register_rows += f"""
        <tr class="border-b hover:bg-gray-50">
            <td class="p-3 font-medium">{name}</td>
            <td class="p-3"><span class="px-2 py-1 rounded text-xs font-bold {get_risk_style(risk)}">{risk}</span></td>
            <td class="p-3">{trust_html}</td>
        </tr>
        """

    # 3. Final HTML Assembly
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 p-8">
        <header class="bg-slate-900 text-white p-6 rounded-xl shadow-2xl mb-8">
            <h1 class="text-3xl font-bold">CISO TPRM GRC Board</h1>
            <p class="text-sm opacity-75">Last Updated: {datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M %p')} IST</p>
        </header>

        <div class="grid grid-cols-4 gap-6 mb-8">
            <div class="bg-white p-6 rounded-lg shadow border-l-4 border-red-600">Critical: {risk_counts.get('Critical', 0)}</div>
            <div class="bg-white p-6 rounded-lg shadow border-l-4 border-orange-500">High: {risk_counts.get('High', 0)}</div>
            <div class="bg-white p-6 rounded-lg shadow border-l-4 border-yellow-400">Medium: {risk_counts.get('Medium', 0)}</div>
            <div class="bg-white p-6 rounded-lg shadow border-l-4 border-green-500">Low: {risk_counts.get('Low', 0)}</div>
        </div>

        <div class="bg-white rounded-lg shadow p-6">
            <h2 class="text-xl font-bold mb-4">Vendor Risk Register</h2>
            <table class="w-full text-left">
                <thead><tr class="bg-gray-100"><th class="p-3">Vendor</th><th class="p-3">Risk</th><th class="p-3">Compliance</th></tr></thead>
                <tbody>{register_rows}</tbody>
            </table>
        </div>
    </body>
    </html>
    """
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == "__main__":
    build_dashboard()
