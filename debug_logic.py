"""
Debug the updated feature extraction logic.
"""

import sys
import os
import tldextract

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from phishing_detector import extract_features

test_urls = [
    "https://phishing-https-site.evil.com/redirect//steal.com",
    "https://suspicious-https-bank.subdomain.phishing.com/redirect//steal.com",
]

for url in test_urls:
    print(f"URL: {url}")
    extracted = tldextract.extract(url)
    print(f"  Subdomain: '{extracted.subdomain}'")
    print(f"  Domain: '{extracted.domain}'")
    print(f"  Suffix: '{extracted.suffix}'")
    
    # Test our updated logic
    has_dash_domain = '-' in extracted.domain
    has_dash_subdomain = '-' in extracted.subdomain if extracted.subdomain else False
    has_dash_combined = has_dash_domain or has_dash_subdomain
    
    all_domain_parts = []
    if extracted.subdomain:
        all_domain_parts.append(extracted.subdomain)
    if extracted.domain:
        all_domain_parts.append(extracted.domain)
    if extracted.suffix:
        all_domain_parts.append(extracted.suffix)
    
    complete_domain = '.'.join(all_domain_parts).lower()
    has_https_token = 'https' in complete_domain
    
    print(f"  Has dash in domain: {has_dash_domain}")
    print(f"  Has dash in subdomain: {has_dash_subdomain}")
    print(f"  Has dash overall: {has_dash_combined}")
    print(f"  Complete domain: '{complete_domain}'")
    print(f"  HTTPS token in complete domain: {has_https_token}")
    
    # Test with actual function
    features = extract_features(url)
    print(f"  Function result - has_dash_in_domain: {features['has_dash_in_domain']}")
    print(f"  Function result - https_token_in_domain: {features['https_token_in_domain']}")
    print("-" * 80)
