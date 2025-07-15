#!/usr/bin/env python3
"""
Quick URL Tester - Simple command line tool for testing URLs
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

from phishing_detector import extract_features


def quick_test(url: str):
    """Quick test of a single URL with simplified output."""
    print(f"\n🔍 Testing: {url}")
    print("-" * 50)
    
    try:
        features = extract_features(url)
        
        # Count risk indicators
        risk_count = 0
        risks = []
        
        if features['has_ip_address']:
            risks.append("Uses IP address")
            risk_count += 1
        
        if features['url_length'] == 'Phishing':
            risks.append("Very long URL")
            risk_count += 1
        elif features['url_length'] == 'Suspicious':
            risks.append("Long URL")
            risk_count += 0.5
            
        if features['is_shortened']:
            risks.append("URL shortener")
            risk_count += 1
            
        if features['double_slash_redirect']:
            risks.append("Double slash redirect")
            risk_count += 1
            
        if features['has_dash_in_domain']:
            risks.append("Dash in domain")
            risk_count += 0.5
            
        if features['subdomain_level'] == 'Phishing':
            risks.append("Many subdomains")
            risk_count += 1
        elif features['subdomain_level'] == 'Suspicious':
            risks.append("Multiple subdomains")
            risk_count += 0.5
            
        if features['https_token_in_domain']:
            risks.append("HTTPS in domain name")
            risk_count += 1
            
        if features['domain_age'] == 'Phishing':
            risks.append("New/unknown domain")
            risk_count += 1
            
        if not features['dns_record']:
            risks.append("No DNS record")
            risk_count += 1
            
        # Simple risk assessment
        if risk_count >= 3:
            status = "🚨 HIGH RISK"
            color = "❌"
        elif risk_count >= 1.5:
            status = "⚠️  SUSPICIOUS"
            color = "🟡"
        elif risk_count >= 0.5:
            status = "⚡ MINOR CONCERNS"
            color = "🟠"
        else:
            status = "✅ LOOKS GOOD"
            color = "✅"
            
        print(f"Status: {color} {status}")
        print(f"Risk Score: {risk_count:.1f}")
        
        if risks:
            print(f"Issues Found: {', '.join(risks)}")
        else:
            print("No major issues detected")
            
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("🛡️  Quick URL Phishing Checker")
        print("Usage: python quick_test.py <url1> [url2] [url3] ...")
        print("\nExamples:")
        print("  python quick_test.py https://google.com")
        print("  python quick_test.py https://bit.ly/test123")
        print("  python quick_test.py https://fake-bank.com")
        sys.exit(1)
    
    urls = sys.argv[1:]
    
    print("🛡️  Quick URL Phishing Checker")
    print("="*50)
    
    for url in urls:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        quick_test(url)
    
    print(f"\n✅ Checked {len(urls)} URL(s)")
