import pandas as pd
from datetime import datetime
import pytz
import os

def run_automation():
    # 1. Get the current time in IST for the logging system
    ist = pytz.timezone('Asia/Kolkata')
    current_time = datetime.now(ist).strftime('%Y-%m-%d %I:%M:%S %p')
    
    excel_file = 'vendor_list.xlsx'
    log_file = 'daily_log.txt'
    html_file = 'index.html'
    
    # Check if the Excel file exists before running
    if not os.path.exists(excel_file):
        log_entry = f"[{current_time}] ERROR: Excel file '{excel_file}' not found.\n"
        with open(log_file, 'a') as f:
            f.write(log_entry)
        print("Error: Excel file missing.")
        return

    try:
        # 2. Read the Excel file
        df = pd.read_excel(excel_file)
        
        # Clean up any empty rows or columns
        df = df.dropna(how='all')
        
        # 3. Convert the Excel data into a clean HTML table
        html_table = df.to_html(index=False, classes='vendor-table')
        
        # 4. Create a complete beautiful webpage layout
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vendor Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f8f9fa; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .meta {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
        .vendor-table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 5px; overflow: hidden; }}
        .vendor-table th {{ background-color: #3498db; color: white; padding: 12px; text-align: left; font-weight: 600; }}
        .vendor-table td {{ padding: 12px; border-bottom: 1px solid #ecf0f1; color: #34495e; }}
        .vendor-table tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .vendor-table tr:hover {{ background-color: #e8f4f8; }}
    </style>
</head>
<body>
    <h1>Active Vendor List Dashboard</h1>
    <div class="meta">Last Automated Update: {current_time} IST</div>
    <div style="overflow-x: auto;">
        {html_table}
    </div>
</body>
</html>"""
        
        # Write the updated HTML webpage file
        with open(html_file, 'w') as f:
            f.write(html_content)
            
        # 5. Write a successful entry to the history log
        total_vendors = len(df)
        log_entry = f"[{current_time}] SUCCESS: Processed {total_vendors} vendors. Webpage updated.\n"
        with open(log_file, 'a') as f:
            f.write(log_entry)
            
        print("Automation ran successfully.")

    except Exception as e:
        # If anything goes wrong, catch the error and log it
        log_entry = f"[{current_time}] FAILED: {str(e)}\n"
        with open(log_file, 'a') as f:
            f.write(log_entry)
        print(f"Automation failed: {e}")

if __name__ == "__main__":
    run_automation()
