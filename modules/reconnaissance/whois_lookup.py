import whois

def whois_lookup(domain):
    w = whois.whois(domain)
    return w


if __name__ == "__main__":
    domain = "google.com"
    result = whois_lookup(domain)
    print(result)