import pandas as pd
import os
import json
import pytz
from datetime import datetime

# --- SETTINGS ---
EXCEL_FILE = 'vendor_list.xlsx'
HTML_FILE = 'index.html'

def generate_clean_html(df):
    """Generates the dashboard HTML without fragile inline escaping."""
    
    # Header logic
    ist = pytz.timezone('Asia/Kolkata')
    sync_time = datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p')
    
    # Generate rows for the tables
    rows_html = ""
    for _, row in df.iterrows():
        # Sanitize variables for JS safely
        vendor = str(row.get('Vendor Name', 'N/A'))
        # Using json.dumps makes it impossible to break the JS string with quotes/backslashes
        js_data = json.dumps({"vendor": vendor})
        
        rows_html += f"""
        <tr>
            <td>{vendor}</td>
            <td>{row.get('Vendor Category', 'N/A')}</td>
            <td>
                <button onclick='alert({js_data})'>View Details</button>
            </td>
        </tr>
        """

    # Return the full template
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Registry Dashboard</title></head>
    <body>
        <h1>Global Supplier Security & Breach Registry</h1>
        <p>Sync Time: {sync_time} IST</p>
        <table border="1">
            <tr><th>Vendor</th><th>Category</th><th>Action</th></tr>
            {rows_html}
        </table>
    </body>
    </html>
    """

def run_dry_run():
    # 1. Validate environment
    if not os.path.exists(EXCEL_FILE):
        print(f"Error: {EXCEL_FILE} not found.")
        return

    # 2. Process Data
    try:
        df = pd.read_excel(EXCEL_FILE)
        print("Successfully read Excel file. Row count:", len(df))
        
        # 3. Generate HTML
        html_output = generate_clean_html(df)
        with open(HTML_FILE, 'w', encoding='utf-8') as f:
            f.write(html_output)
        print("HTML dashboard generated successfully.")
        
    except Exception as e:
        print(f"Dry run failed: {e}")

if __name__ == "__main__":
    run_dry_run()
