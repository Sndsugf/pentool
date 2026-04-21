from nslookup import Nslookup


def ns_lookup(domain):
    dns_query = Nslookup()
    ips_record = dns_query.dns_lookup(domain)
    if ips_record:
        return ips_record.answer


if __name__ == "__main__":
   print( ns_lookup("google.com") )