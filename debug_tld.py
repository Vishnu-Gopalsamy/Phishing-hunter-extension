"""
Debug tldextract parsing for complex domains.
"""

import sys
import os
import tldextract

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

test_urls = [
    "https://phishing-https-site.evil.com/redirect//steal.com",
    "https://suspicious-https-bank.subdomain.phishing.com/redirect//steal.com",
    "https://https-paypal.com/signin",
    "https://secure-https-bank.com"
]

for url in test_urls:
    print(f"URL: {url}")
    extracted = tldextract.extract(url)
    print(f"  Subdomain: '{extracted.subdomain}'")
    print(f"  Domain: '{extracted.domain}'")
    print(f"  Suffix: '{extracted.suffix}'")
    
    full_domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
    print(f"  Full domain: '{full_domain}'")
    print(f"  Has dash in domain: {'-' in extracted.domain}")
    print(f"  HTTPS in full domain: {'https' in full_domain.lower()}")
    print("-" * 60)
