#!/usr/bin/env python3
"""
Interactive URL Checker for Phishing Detection

This script allows you to test your own URLs with the phishing detection system.
"""

import sys
import os
from typing import Dict, Any

# Add current directory to path to import phishing_detector
sys.path.insert(0, os.path.dirname(__file__))

from phishing_detector import extract_features


def display_features(features: Dict[str, Any]) -> None:
    """Display features in a user-friendly format."""
    print("\n" + "="*60)
    print("🔍 PHISHING DETECTION ANALYSIS RESULTS")
    print("="*60)
    
    print("\n📊 ADDRESS BAR FEATURES:")
    print("-" * 30)
    print(f"🌐 IP Address Used: {'❌ YES (Suspicious)' if features['has_ip_address'] else '✅ NO (Good)'}")
    print(f"📏 URL Length: {features['url_length']}")
    print(f"🔗 URL Shortener: {'❌ YES (Suspicious)' if features['is_shortened'] else '✅ NO (Good)'}")
    print(f"↗️  Double Slash Redirect: {'❌ YES (Suspicious)' if features['double_slash_redirect'] else '✅ NO (Good)'}")
    print(f"➖ Dash in Domain: {'❌ YES (Suspicious)' if features['has_dash_in_domain'] else '✅ NO (Good)'}")
    print(f"🌿 Subdomain Level: {features['subdomain_level']}")
    print(f"🔒 HTTPS Token in Domain: {'❌ YES (Suspicious)' if features['https_token_in_domain'] else '✅ NO (Good)'}")
    
    print("\n🌐 DOMAIN-BASED FEATURES:")
    print("-" * 30)
    print(f"📅 Domain Age: {features['domain_age']}")
    print(f"⏰ Registration Length: {features['domain_registration_length']}")
    print(f"🌐 DNS Record Exists: {'✅ YES (Good)' if features['dns_record'] else '❌ NO (Suspicious)'}")
    print(f"📊 Website Popularity: {features['alexa_rank']}")


def calculate_risk_score(features: Dict[str, Any]) -> tuple:
    """Calculate a simple risk score based on features."""
    suspicious_count = 0
    phishing_count = 0
    
    # Count suspicious indicators
    if features['has_ip_address']:
        suspicious_count += 1
    if features['is_shortened']:
        suspicious_count += 1
    if features['double_slash_redirect']:
        suspicious_count += 1
    if features['has_dash_in_domain']:
        suspicious_count += 1
    if features['https_token_in_domain']:
        suspicious_count += 1
        
    # Count phishing indicators
    if features['url_length'] == 'Phishing':
        phishing_count += 1
    if features['subdomain_level'] == 'Phishing':
        phishing_count += 1
    if features['domain_age'] == 'Phishing':
        phishing_count += 1
    if features['domain_registration_length'] == 'Phishing':
        phishing_count += 1
    if features['alexa_rank'] == 'Phishing':
        phishing_count += 1
    if not features['dns_record']:
        phishing_count += 1
        
    # Calculate overall risk
    total_indicators = suspicious_count + phishing_count
    
    if phishing_count >= 3:
        risk_level = "🚨 HIGH RISK - LIKELY PHISHING"
        risk_color = "❌"
    elif total_indicators >= 3:
        risk_level = "⚠️  MEDIUM RISK - SUSPICIOUS"
        risk_color = "🟡"
    elif total_indicators >= 1:
        risk_level = "⚡ LOW RISK - SOME CONCERNS"
        risk_color = "🟠"
    else:
        risk_level = "✅ LOW RISK - APPEARS LEGITIMATE"
        risk_color = "✅"
        
    return risk_level, risk_color, suspicious_count, phishing_count


def analyze_url(url: str) -> None:
    """Analyze a single URL and display results."""
    print(f"\n🔍 Analyzing URL: {url}")
    print(f"📏 URL Length: {len(url)} characters")
    
    try:
        # Extract features
        features = extract_features(url)
        
        # Display features
        display_features(features)
        
        # Calculate and display risk score
        risk_level, risk_color, suspicious_count, phishing_count = calculate_risk_score(features)
        
        print(f"\n{risk_color} OVERALL ASSESSMENT:")
        print("="*60)
        print(f"Risk Level: {risk_level}")
        print(f"Suspicious Indicators: {suspicious_count}")
        print(f"Phishing Indicators: {phishing_count}")
        
        # Provide recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if phishing_count >= 3:
            print("❌ DO NOT visit this URL - high probability of phishing")
            print("❌ Do not enter any personal information")
            print("❌ Report this URL to security authorities")
        elif suspicious_count + phishing_count >= 3:
            print("⚠️  Exercise extreme caution with this URL")
            print("⚠️  Verify the website through official channels")
            print("⚠️  Do not enter sensitive information")
        elif suspicious_count + phishing_count >= 1:
            print("⚡ Some concerning features detected")
            print("⚡ Verify URL legitimacy before proceeding")
            print("⚡ Be cautious with personal information")
        else:
            print("✅ URL appears to have legitimate characteristics")
            print("✅ Standard web safety practices still apply")
            
    except Exception as e:
        print(f"❌ Error analyzing URL: {e}")
        print("This might indicate issues with the URL format or network connectivity.")


def interactive_mode():
    """Run in interactive mode for testing multiple URLs."""
    print("🛡️  PHISHING URL DETECTOR - INTERACTIVE MODE")
    print("="*60)
    print("Enter URLs to analyze (type 'quit' to exit)")
    print("Examples:")
    print("  - https://google.com")
    print("  - https://bit.ly/test123")
    print("  - https://fake-bank.com")
    print("="*60)
    
    while True:
        try:
            url = input("\n🌐 Enter URL to analyze: ").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print("👋 Thank you for using the Phishing URL Detector!")
                break
                
            if not url:
                print("❌ Please enter a valid URL")
                continue
                
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                print(f"🔧 Added HTTPS protocol: {url}")
                
            analyze_url(url)
            
            # Ask if user wants to continue
            continue_choice = input("\n🔄 Analyze another URL? (y/n): ").strip().lower()
            if continue_choice in ['n', 'no']:
                print("👋 Thank you for using the Phishing URL Detector!")
                break
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


def batch_mode(urls: list):
    """Analyze multiple URLs in batch mode."""
    print("🛡️  PHISHING URL DETECTOR - BATCH MODE")
    print("="*60)
    print(f"Analyzing {len(urls)} URLs...")
    
    for i, url in enumerate(urls, 1):
        print(f"\n📊 ANALYSIS {i} of {len(urls)}")
        analyze_url(url)
        
        if i < len(urls):
            input("\n⏳ Press Enter to continue to next URL...")


def main():
    """Main function to run the URL checker."""
    if len(sys.argv) > 1:
        # Command line mode
        urls = sys.argv[1:]
        batch_mode(urls)
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
