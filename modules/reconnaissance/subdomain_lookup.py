import sh
import socket
import time
from concurrent.futures import ThreadPoolExecutor

def subdomain_lookup(domain):
    try:
        str_subs = sh.subfinder("-d" ,domain, _bg=True)
        set_subs = set(str_subs.split("\n")[:-1])
    except Exception as e:
        print(e)
        return
    return fast_filter(set_subs)
#    return list(set_subs)

def check_resolver(subdomain):
    """Function to be run in a thread."""
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip}
    except socket.gaierror:
        return None

def fast_filter(subdomain_list, max_threads=50):
    # print(f"Filtering {len(subdomain_list)} subdomains using {max_threads} threads...")
    
    results = []
    with ThreadPoolExecutor(max_threads) as executor:
        # map() runs the function across the list using the thread pool
        future_results = executor.map(check_resolver, subdomain_list)
        
        for r in future_results:
            if r: # Filter out the 'None' results from failed resolutions
                results.append(r)
        return results



if __name__ == "__main__":
    print(subdomain_lookup("uca.ac.ma"))
    print(subdomain_lookup("1337.ma"))
    start = time.time()
    print(subdomain_lookup("google.com"))
    end = time.time()
    print("google.com subdomain lookup took:", end - start)
    print(subdomain_lookup("kali.org"))
