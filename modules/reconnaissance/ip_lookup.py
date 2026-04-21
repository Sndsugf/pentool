import requests

def ip_lookup(ip_address):
    url = f"https://ipinfo.io/{ip_address}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return {
            "IP": data.get("ip"),
            "Hostname": data.get("hostname"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Country": data.get("country"),
            "Location": data.get("loc"),
            "Organization": data.get("org"),
            "Postal Code": data.get("postal")
        }
    except requests.RequestException as e:
        print(f"Error fetching IP information: {e} via {url}")
        return None

 
if __name__ == "__main__":
    print(ip_lookup("8.8.8.8"))