import os
import requests
from dotenv import load_dotenv

# Load env variables once
load_dotenv()

# --- API Logic ---
def get_ip_info(domain, verbose=False):
    access_key = os.getenv("GET_IP_KEY")
    
    primary_url = f"http://api.ipapi.com/api/{domain}?access_key={access_key}"
    
    try:
        response = requests.get(primary_url)
        data = response.json()
        return parse_data(data, domain, "ipapi", verbose=verbose)
            
    except requests.RequestException as e:
        print(f"Primary API connection error: {e}")

# --- Parsing & Storage ---
def parse_data(data, domain, source, verbose=False):
    # Mapping keys since different APIs use different naming conventions
    if source == "ipapi":
        extracted = {
            "domain": domain,
            "ip": data.get("ip"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "isp": data.get("connection", {}).get("isp"),
            "source": source
        }

    if verbose:
        print("\n" + "="*30)
        print(f"RECON RESULTS: {domain}")
        print(f"IP:      {extracted['ip']}")
        print(f"Loc:     {extracted['city']}, {extracted['country']}")
        print(f"ISP:     {extracted['isp']}")
        print(f"Source:  {extracted['source']}")
        print("="*30 + "\n")

    return extracted

def save_to_db(conn, info):
    if not info: return
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_results (domain, ip, country, city, isp, source)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (info['domain'], info['ip'], info['country'], info['city'], info['isp'], info['source']))
    conn.commit()

# --- Main Execution ---
if __name__ == "__main__":
    target = "uca.ac.ma"
    get_ip_info(target)


# def get_ip(domain):
#     url = f"https://dns.google/resolve?name={domain}"
#     access_key = os.getenv("GET_IP_KEY")
#     print(f"Using access key: {access_key}")
#     url = f"http://api.ipapi.com/api/{domain}?access_key={access_key}"
#     try:
#         response = requests.get(url)
#         response.raise_for_status()
#         data = response.json()
#         #parse this : {'ip': '172.253.115.138', 'type': 'ipv4', 'continent_code': 'NA', 'continent_name': 'North America', 'country_code': 'US', 'country_name': 'United States', 'region_code': 'CA', 'region_name': 'California', 'city': 'Mountain View', 'zip': '94041', 'latitude': 37.38801956176758, 'longitude': -122.07431030273438, 'msa': '41940', 'dma': '807', 'radius': '0', 'ip_routing_type': 'fixed', 'connection_type': 'tx', 'location': {'geoname_id': 7173909, 'capital': 'Washington D.C.', 'languages': [{'code': 'en', 'name': 'English', 'native': 'English'}], 'country_flag': 'https://assets.ipstack.com/flags/us.svg', 'country_flag_emoji': '🇺🇸', 'country_flag_emoji_unicode': 'U+1F1FA U+1F1F8', 'calling_code': '1', 'is_eu': False}, 'time_zone': {'id': 'America/Los_Angeles', 'current_time': '2026-04-15T21:02:44-07:00', 'gmt_offset': -25200, 'code': 'PDT', 'is_daylight_saving': True}, 'currency': {'code': 'USD', 'name': 'US Dollar', 'plural': 'US dollars', 'symbol': '$', 'symbol_native': '$'}, 'connection': {'asn': 15169, 'isp': 'Google', 'sld': '1e100', 'tld': 'net', 'carrier': 'google', 'home': False, 'organization_type': 'Internet Service Provider', 'isic_code': 'J6110', 'naics_code': '517311'}
#         return data
#     except requests.RequestException as e:
#         print(f"Error fetching IP information: {e} via {url}")
#         return []
    

# if __name__ == "__main__":
#     domain = "google.com"
#     ips = get_ip(domain)
#     print(f"IP addresses for {domain}: {ips}")