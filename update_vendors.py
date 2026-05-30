import pandas as pd
import os
import json
import pytz
from datetime import datetime

# --- SETTINGS ---
EXCEL_FILE = 'vendor_list.xlsx'
HTML_FILE = 'index.html'

def get_html_dashboard(df):
    """Generates the full dashboard using safe JSON serialization to prevent syntax errors."""
    
    # 1. Prepare data rows (this replaces your previous fragile string concatenation)
    rows_html = ""
    for _, row in df.iterrows():
        # Sanitize data for the JavaScript modal
        vendor = str(row.get('Vendor Name', 'N/A'))
        category = str(row.get('Vendor Category', 'N/A'))
        
        # Prepare a safe JSON object for the JavaScript function
        modal_data = json.dumps({"vendor": vendor, "category": category})
        
        rows_html += f"""
        <tr>
            <td>{vendor}</td>
            <td>{category}</td>
            <td>
                <button class='drill-down-btn' onclick='triggerModal({modal_data})'>
                    Drill Down 👁️
                </button>
            </td>
        </tr>
        """

    # 2. Return the full HTML template
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Supplier Security & Breach Registry</title>
        <style>
            body {{ font-family: sans-serif; margin: 40px; background: #f4f7f6; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th, td {{ padding: 12px; border: 1px solid #ddd; }}
            .drill-down-btn {{ background: #3182ce; color: white; border: none; padding: 5px 10px; cursor: pointer; }}
        </style>
    </head>
    <body>
        <h1>Global Supplier Security & Breach Registry</h1>
        <p>Sync Time: {datetime.now(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S')} IST</p>
        <table>
            <tr><th>Vendor</th><th>Category</th><th>Action</th></tr>
            {rows_html}
        </table>
        
        <script>
            function triggerModal(data) {{
                alert("Analyzing details for: " + data.vendor + " (" + data.category + ")");
            }}
        </script>
    </body>
    </html>
    """

def run():
    if not os.path.exists(EXCEL_FILE):
        return
    df = pd.read_excel(EXCEL_FILE)
    html = get_html_dashboard(df)
    with open(HTML_FILE, 'w', encoding='utf-8') as f:
        f.write(html)

if __name__ == "__main__":
    run()
