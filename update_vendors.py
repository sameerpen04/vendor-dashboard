import pandas as pd
import os
from datetime import datetime
import pytz

# --- CORE SETTINGS ---
EXCEL_FILE = 'vendor_list.xlsx'
OUTPUT_FILE = 'index.html'

def build_dashboard():
    # Load your vendor register
    df = pd.read_excel(EXCEL_FILE)
    
    # Calculate Risk Counts
    risk_counts = df['Inherent Risk Rating'].value_counts().to_dict()
    
    # Generate HTML with Tailwind CSS
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <script src="https://cdn.tailwindcss.com"></script>
        <title>CISO TPRM GRC Board</title>
    </head>
    <body class="bg-gray-100 p-8">
        <header class="bg-indigo-900 text-white p-6 rounded-lg shadow-lg mb-8">
            <h1 class="text-2xl font-bold">CISO TPRM GRC Board</h1>
            <p class="text-sm opacity-75">Last Updated: {datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M %p')} IST</p>
        </header>

        <div class="grid grid-cols-4 gap-4 mb-8">
            <div class="bg-white p-4 rounded shadow">Critical: {risk_counts.get('Critical', 0)}</div>
            <div class="bg-white p-4 rounded shadow">High: {risk_counts.get('High', 0)}</div>
            <div class="bg-white p-4 rounded shadow">Medium: {risk_counts.get('Medium', 0)}</div>
            <div class="bg-white p-4 rounded shadow">Low: {risk_counts.get('Low', 0)}</div>
        </div>

        <div class="bg-white rounded shadow p-6">
            <div class="flex border-b mb-4">
                <button class="px-4 py-2 border-b-2 border-indigo-600 font-bold">Dashboard</button>
                <button class="px-4 py-2 opacity-50">Vendor Risk Register</button>
                <button class="px-4 py-2 opacity-50">Live Threat Intel</button>
            </div>
            </div>
    </body>
    </html>
    """
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == "__main__":
    build_dashboard()
