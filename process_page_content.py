"""
Page Content Processor

This module provides utilities to fetch and analyze web page content,
looking for phishing indicators in HTML, JavaScript, and forms.
"""

import requests
import re
import logging
import urllib.parse
from typing import Dict, Any, List, Tuple, Optional
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
try:
    import OpenSSL.crypto as crypto
except ImportError:
    crypto = None

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PageContentAnalyzer:
    """Analyzes web page content for phishing indicators."""
    
    def __init__(self):
        # Patterns for suspicious content
        self.sensitive_terms = [
            'password', 'credit card', 'login', 'ssn', 'social security',
            'verify', 'bank', 'account', 'update', 'confirm', 'secure'
        ]
        
        self.js_suspicious_patterns = [
            'document.cookie', 'window.location', 'eval(', 'fromCharCode',
            'onsubmit', 'addEventListener("submit"', '.submit()', 'keylogger',
            'obfuscated', 'document.forms[0]'
        ]
        
        self.common_brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'facebook', 
            'google', 'chase', 'bank', 'netflix', 'instagram', 'linkedin'
        ]
    
    def fetch_page_content(self, url: str, timeout: int = 5) -> Optional[str]:
        """
        Fetches HTML content from a URL with timeout.
        
        Args:
            url: URL to fetch
            timeout: Request timeout in seconds
            
        Returns:
            Page HTML content or None if failed
        """
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml',
                'Accept-Language': 'en-US,en;q=0.9'
            }
            
            # Disable SSL warnings for this request
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            if response.status_code != 200:
                logger.warning(f"Failed to fetch {url}: Status code {response.status_code}")
                return None
                
            return response.text
            
        except requests.RequestException as e:
            logger.error(f"Error fetching content from {url}: {e}")
            return None
    
    def analyze_page(self, url: str, html_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyzes page content for phishing indicators.
        
        Args:
            url: The page URL
            html_content: HTML content (if already fetched)
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'html_analysis': {},
            'js_analysis': {},
            'form_analysis': {},
            'ssl_analysis': {},
            'risk_score': 0,
            'flags': []
        }
        
        if not html_content:
            html_content = self.fetch_page_content(url)
        
        if not html_content:
            results['flags'].append("Failed to fetch page content")
            return results
        
        # Analyze HTML structure
        html_risk, html_flags, html_analysis = self.analyze_html(html_content, url)
        results['html_analysis'] = html_analysis
        results['flags'].extend(html_flags)
        results['risk_score'] += html_risk
        
        # Analyze JavaScript
        js_risk, js_flags, js_analysis = self.analyze_javascript(html_content)
        results['js_analysis'] = js_analysis
        results['flags'].extend(js_flags)
        results['risk_score'] += js_risk
        
        # Analyze forms
        form_risk, form_flags, form_analysis = self.analyze_forms(html_content, url)
        results['form_analysis'] = form_analysis
        results['flags'].extend(form_flags)
        results['risk_score'] += form_risk
        
        # Check SSL certificate
        ssl_risk, ssl_flags, ssl_info = self.check_ssl(url)
        results['ssl_analysis'] = ssl_info
        results['flags'].extend(ssl_flags)
        results['risk_score'] += ssl_risk
        
        # Cap risk score
        results['risk_score'] = min(100, results['risk_score'])
        
        return results
    
    def analyze_html(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Analyzes HTML structure and content.
        
        Args:
            content: HTML content
            url: URL of the page
            
        Returns:
            Tuple of (risk_score, flags, detailed_analysis)
        """
        risk_score = 0
        flags = []
        analysis = {
            'title_mismatch': False,
            'brand_mentions': [],
            'hidden_elements': 0,
            'iframe_count': 0,
            'external_resources': 0,
            'suspicious_elements': []
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check page title
            title = soup.title.text if soup.title else ""
            analysis['page_title'] = title
            
            # Extract domain from URL for comparison
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            
            # Check for title mismatch with domain
            analysis['title_mismatch'] = main_domain.lower() not in title.lower()
            if analysis['title_mismatch']:
                flags.append("Page title doesn't match domain")
                risk_score += 15
            
            # Check for brand mentions in content
            page_text = soup.get_text().lower()
            for brand in self.common_brands:
                if brand.lower() in page_text and brand.lower() not in domain.lower():
                    analysis['brand_mentions'].append(brand)
                    flags.append(f"References to {brand} found, but not in domain")
                    risk_score += 10
                    break  # Only count one brand mention for risk score
            
            # Check for hidden elements
            hidden_elements = soup.select('[style*="display: none"], [style*="display:none"], [style*="visibility: hidden"]')
            analysis['hidden_elements'] = len(hidden_elements)
            if analysis['hidden_elements'] > 2:  # Allow a couple for legitimate sites
                flags.append(f"Found {analysis['hidden_elements']} hidden elements")
                risk_score += 15
            
            # Check for iframes
            iframes = soup.find_all('iframe')
            analysis['iframe_count'] = len(iframes)
            if analysis['iframe_count'] > 0:
                flags.append(f"Found {analysis['iframe_count']} iframes")
                risk_score += 5 * min(analysis['iframe_count'], 3)  # Cap at 15 points
            
            # Check for external resources
            external_resources = 0
            parsed_domain = urllib.parse.urlparse(url).netloc
            for tag in soup.find_all(['script', 'link', 'img']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith(('http://', 'https://')):
                    try:
                        resource_domain = urllib.parse.urlparse(src).netloc
                        if resource_domain and resource_domain != parsed_domain:
                            external_resources += 1
                    except:
                        pass
            
            analysis['external_resources'] = external_resources
            if external_resources > 10:  # Many external resources can be suspicious
                flags.append(f"High number of external resources: {external_resources}")
                risk_score += min(20, external_resources)
            
            # Look for suspicious meta elements
            meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
            if meta_refresh:
                analysis['suspicious_elements'].append('meta-refresh')
                flags.append("Page uses meta refresh (possible redirect)")
                risk_score += 10
            
        except Exception as e:
            flags.append(f"HTML analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def analyze_javascript(self, content: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Analyzes JavaScript code for suspicious patterns.
        
        Args:
            content: HTML content with embedded scripts
            
        Returns:
            Tuple of (risk_score, flags, detailed_analysis)
        """
        risk_score = 0
        flags = []
        analysis = {
            'suspicious_patterns': [],
            'obfuscation_detected': False,
            'event_handlers': 0,
            'eval_usage': False
        }
        
        try:
            # Extract all script content
            soup = BeautifulSoup(content, 'html.parser')
            
            # Get inline scripts
            script_tags = soup.find_all('script')
            script_content = ' '.join([tag.string for tag in script_tags if tag.string])
            
            # Check for suspicious patterns
            for pattern in self.js_suspicious_patterns:
                if pattern in script_content:
                    analysis['suspicious_patterns'].append(pattern)
                    flags.append(f"Suspicious JavaScript: {pattern}")
                    risk_score += 10
            
            # Check for obfuscation (common in malicious scripts)
            obfuscation_indicators = [
                'fromCharCode', 'unescape', 'escape', 'eval', 'atob', 'btoa',
                'String.fromCharCode', 'parseInt', 'String.charAt'
            ]
            
            obfuscation_score = 0
            for indicator in obfuscation_indicators:
                if indicator in script_content:
                    obfuscation_score += 1
            
            # Also check for very long strings or lots of hex/unicode
            hex_pattern = r'\\x[0-9a-f]{2}'
            unicode_pattern = r'\\u[0-9a-f]{4}'
            hex_matches = len(re.findall(hex_pattern, script_content))
            unicode_matches = len(re.findall(unicode_pattern, script_content))
            
            if hex_matches + unicode_matches > 20:
                obfuscation_score += 2
            
            if obfuscation_score >= 2:
                analysis['obfuscation_detected'] = True
                flags.append("JavaScript obfuscation detected")
                risk_score += 25
            
            # Count event handlers (especially form-related)
            event_handlers = re.findall(r'on(submit|click|load|change|mouse|key|focus|blur)', script_content)
            analysis['event_handlers'] = len(event_handlers)
            
            if analysis['event_handlers'] > 5:  # Many event handlers can be suspicious
                flags.append(f"High number of event handlers: {analysis['event_handlers']}")
                risk_score += 10
            
            # Check for direct eval usage
            analysis['eval_usage'] = 'eval(' in script_content
            if analysis['eval_usage']:
                flags.append("Direct eval() usage detected")
                risk_score += 15
                
        except Exception as e:
            flags.append(f"JavaScript analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def analyze_forms(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Analyzes forms for phishing indicators.
        
        Args:
            content: HTML content
            url: Page URL
            
        Returns:
            Tuple of (risk_score, flags, detailed_analysis)
        """
        risk_score = 0
        flags = []
        analysis = {
            'form_count': 0,
            'password_fields': 0,
            'sensitive_fields': 0,
            'external_action': False,
            'missing_security': False
        }
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            analysis['form_count'] = len(forms)
            
            domain = urllib.parse.urlparse(url).netloc
            
            for form in forms:
                # Check form action
                action = form.get('action', '')
                if action:
                    # Check if action is an absolute URL
                    if action.startswith(('http://', 'https://')):
                        action_domain = urllib.parse.urlparse(action).netloc
                        # If action domain doesn't match the current domain
                        if action_domain != domain:
                            analysis['external_action'] = True
                            flags.append(f"Form submits to external domain: {action_domain}")
                            risk_score += 30
                
                # Check for password fields
                password_fields = form.find_all('input', {'type': 'password'})
                analysis['password_fields'] += len(password_fields)
                
                # Check for sensitive input fields
                inputs = form.find_all('input')
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    field_id = input_field.get('id', '').lower()
                    field_placeholder = input_field.get('placeholder', '').lower()
                    
                    for term in self.sensitive_terms:
                        if (term in field_name or term in field_id or term in field_placeholder):
                            analysis['sensitive_fields'] += 1
                            break
                
                # Check security indicators
                missing_security = False
                
                # Should have HTTPS if collecting sensitive data
                if url.startswith('http://') and analysis['sensitive_fields'] > 0:
                    missing_security = True
                    flags.append("Form collects sensitive data over HTTP")
                    risk_score += 20
                
                # Check for CSRF token (can be various names)
                csrf_present = False
                for input_field in inputs:
                    field_name = input_field.get('name', '').lower()
                    if any(token in field_name for token in ['csrf', 'token', 'nonce']):
                        csrf_present = True
                        break
                
                if analysis['sensitive_fields'] > 0 and not csrf_present:
                    missing_security = True
                    flags.append("Form lacks CSRF protection")
                    risk_score += 10
                
                analysis['missing_security'] = missing_security
            
            # Overall form risk assessment
            if analysis['password_fields'] > 0:
                flags.append(f"Form contains {analysis['password_fields']} password fields")
                risk_score += 15
            
            if analysis['sensitive_fields'] > 2:
                flags.append(f"Form collects multiple sensitive fields ({analysis['sensitive_fields']})")
                risk_score += 10
                
        except Exception as e:
            flags.append(f"Form analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def check_ssl(self, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """
        Checks SSL certificate validity.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (risk_score, flags, detailed_analysis)
        """
        risk_score = 0
        flags = []
        ssl_info = {
            'has_ssl': False,
            'cert_valid': False,
            'cert_matches_domain': False,
            'cert_expiry': None,
            'cert_authority': None
        }
        
        # Only check HTTPS URLs
        if not url.startswith('https://'):
            ssl_info['has_ssl'] = False
            return risk_score, flags, ssl_info
        
        try:
            if crypto is None:
                flags.append("SSL check skipped: pyOpenSSL not installed")
                return risk_score, flags, ssl_info
                
            ssl_info['has_ssl'] = True
            
            # Parse URL to get hostname
            hostname = urllib.parse.urlparse(url).netloc
            if ':' in hostname:
                hostname = hostname.split(':')[0]  # Remove port if present
            
            # Create SSL context
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Check if certificate matches domain
                    cert_domains = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if 'subjectAltName' in str(ext.get_short_name()):
                            data = ext.get_data()
                            # Parse SANs (simplified approach)
                            sans = str(data)
                            for domain in sans.split(','):
                                if 'DNS:' in domain:
                                    cert_domains.append(domain.split('DNS:')[1].strip())
                    
                    common_name = x509.get_subject().CN
                    if common_name:
                        cert_domains.append(common_name)
                    
                    # Check if any cert domain matches our URL domain
                    domain_match = False
                    for cert_domain in cert_domains:
                        # Check for exact match or wildcard
                        if cert_domain == hostname or (cert_domain.startswith('*.') and hostname.endswith(cert_domain[1:])):
                            domain_match = True
                            break
                    
                    ssl_info['cert_matches_domain'] = domain_match
                    if not domain_match:
                        flags.append("SSL certificate doesn't match domain")
                        risk_score += 25
                    
                    # Check expiry
                    expiry = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    ssl_info['cert_expiry'] = expiry.isoformat()
                    
                    if expiry < datetime.now():
                        flags.append("SSL certificate has expired")
                        risk_score += 30
                        ssl_info['cert_valid'] = False
                    else:
                        ssl_info['cert_valid'] = True
                    
                    # Check issuer (CA)
                    issuer = x509.get_issuer()
                    ssl_info['cert_authority'] = issuer.CN if hasattr(issuer, 'CN') else str(issuer)
                    
                    # Self-signed certificates are suspicious
                    if issuer.CN == x509.get_subject().CN:
                        flags.append("Self-signed SSL certificate")
                        risk_score += 25
            
        except ssl.SSLError as e:
            flags.append(f"SSL Error: {str(e)}")
            risk_score += 20
        except Exception as e:
            flags.append(f"Failed to verify SSL: {str(e)}")
        
        return risk_score, flags, ssl_info


# Usage example
if __name__ == "__main__":
    analyzer = PageContentAnalyzer()
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://github.com",
        "http://example.org"
    ]
    
    print("\n" + "="*70)
    print("PAGE CONTENT ANALYSIS TEST")
    print("="*70)
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        try:
            results = analyzer.analyze_page(url)
            
            print(f"Risk score: {results['risk_score']:.1f}")
            
            if results['flags']:
                print("Detected issues:")
                for flag in results['flags']:
                    print(f"- {flag}")
            else:
                print("No issues detected")
                
            print("\nForm analysis:")
            forms = results['form_analysis']
            if forms['form_count'] > 0:
                print(f"- Forms: {forms['form_count']}")
                print(f"- Password fields: {forms['password_fields']}")
                print(f"- Sensitive fields: {forms['sensitive_fields']}")
            else:
                print("- No forms detected")
                
            print("\nJavaScript analysis:")
            js = results['js_analysis']
            print(f"- Obfuscation detected: {js['obfuscation_detected']}")
            print(f"- Event handlers: {js['event_handlers']}")
            print(f"- Suspicious patterns: {len(js['suspicious_patterns'])}")
            
        except Exception as e:
            print(f"Error analyzing {url}: {e}")
            
        print("-"*70)
