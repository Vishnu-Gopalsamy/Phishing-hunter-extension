# 🛡️ How to Check Your Own URLs

This guide shows you different ways to test your own URLs for phishing characteristics.

## 🚀 Quick Methods

### Method 1: Interactive Mode (Recommended for beginners)
```bash
python check_url.py
```
Then enter URLs one by one when prompted.

### Method 2: Command Line (Quick testing)
```bash
python quick_test.py https://your-url-here.com
```

### Method 3: Multiple URLs at once
```bash
python quick_test.py https://google.com https://bit.ly/test123 https://suspicious-site.com
```

### Method 4: Python Code (For developers)
```python
from phishing_detector import extract_features, check_url

# Quick check
result = check_url("https://your-url.com")
print(result)  # Returns: SAFE, CAUTION, SUSPICIOUS, or DANGEROUS

# Detailed analysis
features = extract_features("https://your-url.com")
print(features)  # Shows all detected features
```

## 📋 Example Sessions

### Interactive Mode Example:
```
🛡️  PHISHING URL DETECTOR - INTERACTIVE MODE
============================================================
Enter URLs to analyze (type 'quit' to exit)

🌐 Enter URL to analyze: google.com
🔧 Added HTTPS protocol: https://google.com

🔍 Analyzing URL: https://google.com
📏 URL Length: 18 characters

============================================================
🔍 PHISHING DETECTION ANALYSIS RESULTS
============================================================

📊 ADDRESS BAR FEATURES:
------------------------------
🌐 IP Address Used: ✅ NO (Good)
📏 URL Length: Legitimate
🔗 URL Shortener: ✅ NO (Good)
↗️  Double Slash Redirect: ✅ NO (Good)
➖ Dash in Domain: ✅ NO (Good)
🌿 Subdomain Level: Legitimate
🔒 HTTPS Token in Domain: ✅ NO (Good)

🌐 DOMAIN-BASED FEATURES:
------------------------------
📅 Domain Age: Legitimate
⏰ Registration Length: Legitimate
🌐 DNS Record Exists: ✅ YES (Good)
📊 Website Popularity: Legitimate

✅ OVERALL ASSESSMENT:
============================================================
Risk Level: ✅ LOW RISK - APPEARS LEGITIMATE
Suspicious Indicators: 0
Phishing Indicators: 0

💡 RECOMMENDATIONS:
✅ URL appears to have legitimate characteristics
✅ Standard web safety practices still apply
```

### Quick Test Example:
```bash
python quick_test.py fake-bank.com suspicious-https-site.com

🛡️  Quick URL Phishing Checker
==================================================

🔍 Testing: https://fake-bank.com
--------------------------------------------------
Status: ⚠️  SUSPICIOUS
Risk Score: 1.5
Issues Found: Dash in domain, New/unknown domain

🔍 Testing: https://suspicious-https-site.com
--------------------------------------------------
Status: 🚨 HIGH RISK  
Risk Score: 3.0
Issues Found: Dash in domain, HTTPS in domain name, New/unknown domain

✅ Checked 2 URL(s)
```

## ⚡ One-Line Testing

For quick Python testing:
```python
# Import and test in one line
from phishing_detector import check_url; print(check_url("https://your-url.com"))
```

## 🔍 Understanding Results

### Risk Levels:
- **✅ SAFE**: No suspicious indicators found
- **⚡ CAUTION**: Minor concerns detected  
- **⚠️ SUSPICIOUS**: Multiple red flags present
- **🚨 DANGEROUS**: High probability of phishing

### Common Red Flags:
- ❌ **Uses IP address** instead of domain name
- ❌ **Very long URLs** (>75 characters often suspicious)
- ❌ **URL shorteners** (bit.ly, tinyurl.com, etc.)
- ❌ **Double slash redirects** (//evil.com)
- ❌ **Dashes in domain** (fake-bank.com)
- ❌ **"https" in domain name** (https-paypal.com)
- ❌ **Many subdomains** (a.b.c.d.site.com)
- ❌ **New domains** (<6 months old)
- ❌ **No DNS record** (domain doesn't resolve)

## 🛠️ Troubleshooting

### If you get errors:
1. **Network Issues**: Some features require internet connection for WHOIS/DNS lookups
2. **Invalid URL**: Make sure URL is properly formatted
3. **Missing Dependencies**: Run `pip install -r requirements.txt`

### Common URL Formats:
- ✅ `https://example.com`
- ✅ `http://example.com/path`
- ✅ `example.com` (will auto-add https://)
- ❌ `just-text-not-url`

## 📝 Testing Your Own Website

If you want to test your own website:
```python
from phishing_detector import extract_features

# Test your site
my_site = "https://mywebsite.com"
features = extract_features(my_site)

# Check each feature
for feature, value in features.items():
    print(f"{feature}: {value}")
```

## 🎯 Best Practices

1. **Test before sharing**: Always check URLs before sharing them
2. **Multiple indicators**: One red flag doesn't always mean phishing
3. **Context matters**: Consider the source and context of the URL
4. **Stay updated**: Keep the detection system updated
5. **When in doubt**: Don't click - verify through official channels

## 🚨 Emergency Protocol

If you find a **DANGEROUS** URL:
1. ❌ **DO NOT** visit the URL
2. ❌ **DO NOT** enter any information
3. ✅ **Report** to appropriate authorities
4. ✅ **Warn** others who might have received it
5. ✅ **Verify** through official channels if it claims to be from a known organization

Remember: This tool helps identify suspicious characteristics, but always use your judgment and follow cybersecurity best practices! 🛡️
