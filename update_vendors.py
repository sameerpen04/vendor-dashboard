import pandas as pd
from datetime import datetime
import pytz
import os
import requests
import xml.etree.ElementTree as ET
import re
import json

def fetch_live_threat_intel():
    """
    Consolidates enterprise open-source threat intelligence feeds.
    """
    intel_database = []
    
    # 1. CISA KEV Catalog Feed
    try:
        cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(cisa_url, timeout=10)
        if response.status_code == 200:
            vulnerabilities = response.json().get('vulnerabilities', [])
            for vuln in vulnerabilities[-150:]:
                intel_database.append({
                    'title': f"CISA KEV: {vuln.get('cveID')}",
                    'summary': f"{vuln.get('vendorProject')} - {vuln.get('shortDescription')}",
                    'source': "CISA KEV Catalog"
                })
    except Exception:
        pass

    # 2. RSS Security Feeds (BleepingComputer, Cyberwire, SANS ISC)
    rss_feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "TheCyberwire": "https://thecyberwire.com/feeds/rss.xml",
        "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed.xml"
    }
    
    for source_name, url in rss_feeds.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                for item in root.findall('.//item')[:40]:
                    title = item.find('title').text if item.find('title') is not None else ""
                    summary = item.find('description').text if item.find('description') is not None else ""
                    clean_summary = re.sub('<[^<]+?>', '', summary) if summary else ""
                    intel_database.append({
                        'title': title,
                        'summary': clean_summary,
                        'source': source_name
                    })
        except Exception:
            pass
            
    return intel_database

def compute_static_grc_profile(vendor_name):
    """
    GRC Profiling Engine executed ONLY ONCE per vendor entry to generate 
    baseline properties, validated domains, and specific compliance paths.
    """
    v_upper = str(vendor_name).upper().strip()
    domain_token = re.sub(r'[^A-Z0-9]', '', v_upper.split()[0]).lower() if v_upper.split() else "vendor"
    
    # Default Base Fallbacks
    category = "SaaS / General Business Operations"
    url = f"https://www.{domain_token}.com"
    trust_center = "https://trust.vanta.com" 
    services = "General commercial software or corporate execution operational platform support."
    compliance_label = "SOC 2 Type II / ISO 27001 Certified"
    compliance_url = "https://trust.vanta.com"
    scope_of_business = "Standard Internal System Dependency"
    data_processed = "Commercial Metadata & General Content Records"
    impact_of_breach = "Moderate Operational Process Interruption"
    inherent_risk = "Medium"

    # Logistics Layer
    if any(k in v_upper for k in ["FEDEX", "DHL", "UPS", "BLUEDART", "COURIER", "LOGISTICS", "SHIPPING"]):
        category = "Courier, Supply Chain & Global Logistics Services"
        url = "https://www.fedex.com" if "FEDEX" in v_upper else "https://www.dhl.com"
        trust_center = "https://www.fedex.com/en-us/trust-center.html" if "FEDEX" in v_upper else "https://www.dhl.com/global-en/home/footer/local-privacy-notice.html"
        services = "Physical global logistics routing, shipping supply chains, asset transport, and distribution tracking systems."
        compliance_label = "ISO 9001 / ISO 27001 Validated"
        compliance_url = "https://www.fedex.com/en-us/trust-center/privacy.html"
        scope_of_business = "Physical Infrastructure & Supply Chain Dependence"
        data_processed = "Corporate Physical Addresses, Shipping Manifests, PII, Customs Data"
        impact_of_breach = "Supply Chain Disruptions, Asset Tracking Loss, and Corporate PII Leakage"
        inherent_risk = "High"

    # Cloud Infrastructure Layer
    elif any(k in v_upper for k in ["CLOUD", "AZURE", "AWS", "GOOGLE", "MONGODB", "SNOWFLAKE", "ORACLE", "AMAZON"]):
        category = "Cloud Infrastructure & Hyper-Scale Hosting"
        url = "https://aws.amazon.com" if "AWS" in v_upper else "https://azure.microsoft.com"
        trust_center = "https://aws.amazon.com/compliance/trust-center/" if "AWS" in v_upper else "https://servicetrust.microsoft.com/"
        services = "Core multi-tenant cloud storage, multi-region computing resources, network hosting, and database backends."
        compliance_label = "SOC 1,2,3 / FedRAMP High"
        compliance_url = "https://aws.amazon.com/compliance/programs/" if "AWS" in v_upper else "https://azure.microsoft.com/en-us/explore/compliance/"
        scope_of_business = "High Systemic Core Hosting Dependency"
        data_processed = "Production Data Repositories, PII, Underlying Network Configurations"
        impact_of_breach = "Widespread Systemic Outages, Total Infrastructure Down-Time, Broad Data Disclosure"
        inherent_risk = "Critical"

    # Identity / Finance Layer
    elif any(k in v_upper for k in ["1PASSWORD", "OKTA", "CHASE", "BANK", "ICICI", "REVOLUT", "STRIPE", "PAYMENT", "HSBC", "PAYTM"]):
        category = "Identity Management / Core Enterprise Financial Processor"
        url = "https://okta.com" if "OKTA" in v_upper else "https://1password.com"
        trust_center = "https://www.okta.com/trust-center/" if "OKTA" in v_upper else "https://1password.com/security/"
        services = "Privileged single sign-on authentication paths, corporate credential storage, or core transactional fiscal ledger clearing."
        compliance_label = "SOC 2 Type II / PCI-DSS Level 1 Verified"
        compliance_url = "https://www.okta.com/trust-center/compliance/" if "OKTA" in v_upper else "https://support.1password.com/security-assessments/"
        scope_of_business = "Privileged Access Integration & Financial Gateway Control"
        data_processed = "Cryptographic Hashes, Master Passwords, Active Corporate API Keys, Bank Accounts"
        impact_of_breach = "Direct Lateral Identity Compromise, Corporate Account Takeover, Direct Financial Loss"
        inherent_risk = "Critical"

    # Business Application Layer
    elif any(k in v_upper for k in ["HUBSPOT", "SALESFORCE", "ATLASSIAN", "JIRA", "CONFLUENCE", "VANTA", "SAGE", "SMARTSHEET", "ZOOM", "SLACK"]):
        category = "Enterprise Business SaaS Application Suite"
        url = "https://www.salesforce.com" if "SALESFORCE" in v_upper else "https://www.hubspot.com"
        trust_center = "https://trust.salesforce.com" if "SALESFORCE" in v_upper else "https://www.hubspot.com/security"
        services = "Central CRM client metrics tracking, project ticketing systems, code pipelines, or internal corporate chat histories."
        compliance_label = "SOC 2 Type II / ISO 27001 Verified"
        compliance_url = "https://compliance.sales
