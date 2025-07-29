def whois_lookup(domain):
    print(f"[+] Performing WHOIS lookup on: {domain}")
    try:
        w = whois.whois(domain)

        if not w.domain_name:
            print("[-] No WHOIS data found. Domain may not exist.")
            return

        print("=" * 40)
        print(f"Domain Name   : {w.domain_name}")
        print(f"Registrar     : {w.registrar}")
        print(f"Creation Date : {w.creation_date}")
        print(f"Expiration    : {w.expiration_date}")
        print(f"Updated Date  : {w.updated_date}")
        print(f"Name Servers  : {w.name_servers}")
        print(f"Status        : {w.status}")
        print(f"Emails        : {w.emails}")
        print("=" * 40)

        return w
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")