"""
Phishing URL Detection App - Layered Approach

This module implements a multi-layered detection system where URLs pass through
progressively sophisticated analysis layers for comprehensive phishing detection.
"""

import os
import sys
import re
import urllib.parse
import tldextract
import socket
import whois
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import joblib
import json
import logging
from enum import Enum

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level enumeration for clear classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"

class DetectionLayer:
    """Base class for detection layers."""
    
    def __init__(self, name: str, weight: float = 1.0):
        self.name = name
        self.weight = weight
        self.enabled = True
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL and return results."""
        raise NotImplementedError

class Layer1_BasicValidation(DetectionLayer):
    """
    Layer 1: Basic URL Validation & Quick Checks
    - URL format validation
    - Basic malicious patterns
    - Quick blacklist checks
    """
    
    def __init__(self):
        super().__init__("Basic Validation", weight=0.8)
        
        # Known malicious patterns
        self.malicious_patterns = [
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.',  # Multiple dashes
            r'(paypal|ebay|amazon|microsoft|apple|google).*[0-9]+\..*',  # Brand + numbers
            r'(secure|login|account|verify|update).*[0-9]+\.',  # Security terms + numbers
        ]
        
        # Quick blacklist (simplified)
        self.blacklisted_domains = {
            'malicious-site.com', 'phishing-test.org', 'fake-bank.net'
        }
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform basic validation checks."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {},
            'passed': True
        }
        
        try:
            # 1. URL format validation
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                results['flags'].append("Invalid URL format")
                results['risk_score'] += 30
                results['passed'] = False
            
            # 2. Length check (extreme cases)
            if len(url) > 2000:
                results['flags'].append("Extremely long URL")
                results['risk_score'] += 20
            elif len(url) > 200:
                results['flags'].append("Very long URL")
                results['risk_score'] += 10
            
            # 3. Malicious pattern detection
            for pattern in self.malicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    results['flags'].append(f"Malicious pattern detected: {pattern}")
                    results['risk_score'] += 25
            
            # 4. Quick blacklist check
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if domain in self.blacklisted_domains:
                results['flags'].append("Domain in blacklist")
                results['risk_score'] += 50
                results['passed'] = False
            
            # 5. Protocol check
            if parsed.scheme not in ['http', 'https']:
                results['flags'].append("Unusual protocol")
                results['risk_score'] += 15
            
            results['details'] = {
                'url_length': len(url),
                'domain': domain,
                'protocol': parsed.scheme,
                'pattern_matches': len([p for p in self.malicious_patterns if re.search(p, url, re.IGNORECASE)])
            }
            
        except Exception as e:
            results['flags'].append(f"Validation error: {str(e)}")
            results['risk_score'] = 40
            results['passed'] = False
        
        return results

class Layer2_FeatureAnalysis(DetectionLayer):
    """
    Layer 2: Feature Analysis
    - Domain-based features
    - URL structure analysis
    - WHOIS data analysis
    """
    
    def __init__(self):
        super().__init__("Feature Analysis", weight=1.0)
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL features."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'details': {}
        }
        
        try:
            # Extract features
            features = extract_features(url)
            
            # Assess risk based on features
            risk_score = 0.0
            
            # 1. Check for IP address in URL
            if features.get('has_ip_address', False):
                results['flags'].append("IP address used in URL")
                risk_score += 20
            
            # 2. Check URL length
            if features.get('url_length') == 'Suspicious':
                results['flags'].append("Suspicious URL length")
                risk_score += 15
            elif features.get('url_length') == 'Phishing':
                results['flags'].append("Very long URL")
                risk_score += 30
            
            # 3. Check for shortened URL
            if features.get('is_shortened', False):
                results['flags'].append("URL shortening service detected")
                risk_score += 25
            
            # 4. Check for double slash redirect
            if features.get('double_slash_redirect', False):
                results['flags'].append("Double slash redirect detected")
                risk_score += 10
            
            # 5. Check for dash in domain
            if features.get('has_dash_in_domain', False):
                results['flags'].append("Domain contains dashes")
                risk_score += 15
            
            # 6. Check subdomain level
            if features.get('subdomain_level') == 'Suspicious':
                results['flags'].append("Suspicious subdomain depth")
                risk_score += 20
            elif features.get('subdomain_level') == 'Phishing':
                results['flags'].append("Excessive subdomain levels")
                risk_score += 35
            
            # 7. Check for HTTPS in domain (not in protocol)
            if features.get('https_token_in_domain', False):
                results['flags'].append("HTTPS token in domain name")
                risk_score += 40
            
            # 8. Check domain age
            if features.get('domain_age') == 'Phishing':
                results['flags'].append("Domain registered less than 6 months ago")
                risk_score += 25
            
            # 9. Check domain expiry
            if features.get('domain_registration_length') == 'Phishing':
                results['flags'].append("Domain expires in less than 1 year")
                risk_score += 15
            
            # 10. Check DNS record
            if not features.get('dns_record', True):
                results['flags'].append("No DNS record found")
                risk_score += 30
            
            # Set final risk score (cap at 100)
            results['risk_score'] = min(100, risk_score)
            results['details'] = features
            
        except Exception as e:
            results['flags'].append(f"Feature analysis error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results

class Layer2_ContentAnalysis(DetectionLayer):
    """
    Layer 2+: Content Analysis
    - Examines HTML structure and content
    - Analyzes JavaScript patterns
    - Detects suspicious form behaviors
    - Checks for SSL certificate issues
    """
    
    def __init__(self):
        super().__init__("Content Analysis", weight=1.2)
        self.sensitive_terms = [
            'password', 'credit card', 'login', 'ssn', 'social security',
            'verify', 'bank', 'account', 'update', 'confirm', 'secure'
        ]
        self.js_suspicious_patterns = [
            'document.cookie', 'window.location', 'eval(', 'fromCharCode',
            'onsubmit', 'addEventListener("submit"', '.submit()', 'keylogger',
            'obfuscated', 'document.forms[0]'
        ]
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze page content and behavior."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': [],
            'content_analysis': {},
            'ssl_info': {},
            'form_analysis': {},
            'js_analysis': {}
        }
        
        try:
            # Only proceed if URL is valid and accessible
            if not url.startswith(('http://', 'https://')):
                results['flags'].append("Skipping content analysis - invalid URL protocol")
                return results
            
            # Get page content
            content = self._fetch_page_content(url)
            if not content:
                results['flags'].append("Failed to fetch page content")
                results['risk_score'] = 30
                return results
            
            # Analyze HTML structure
            html_risk, html_flags, html_analysis = self._analyze_html(content, url)
            results['content_analysis'] = html_analysis
            results['flags'].extend(html_flags)
            results['risk_score'] += html_risk
            
            # Analyze JavaScript
            js_risk, js_flags, js_analysis = self._analyze_javascript(content)
            results['js_analysis'] = js_analysis
            results['flags'].extend(js_flags)
            results['risk_score'] += js_risk
            
            # Analyze forms
            form_risk, form_flags, form_analysis = self._analyze_forms(content, url)
            results['form_analysis'] = form_analysis
            results['flags'].extend(form_flags)
            results['risk_score'] += form_risk
            
            # Check SSL certificate
            ssl_risk, ssl_flags, ssl_info = self._check_ssl(url)
            results['ssl_info'] = ssl_info
            results['flags'].extend(ssl_flags)
            results['risk_score'] += ssl_risk
            
            # Cap risk score
            results['risk_score'] = min(100, results['risk_score'])
            
        except Exception as e:
            results['flags'].append(f"Content analysis error: {str(e)}")
            results['risk_score'] = 0  # Don't penalize for analysis failures
            
        return results
    
    def _fetch_page_content(self, url: str) -> Optional[str]:
        """Fetch page content with timeout."""
        try:
            import requests
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml',
                'Accept-Language': 'en-US,en;q=0.9'
            }
            response = requests.get(url, headers=headers, timeout=5, verify=False)
            return response.text
        except Exception as e:
            logger.error(f"Failed to fetch content for {url}: {e}")
            return None
    
    def _analyze_html(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze HTML content for suspicious patterns."""
        risk_score = 0
        flags = []
        analysis = {
            'title_mismatch': False,
            'brand_mentions': [],
            'hidden_elements': 0,
            'iframe_count': 0,
            'external_resources': 0,
            'suspicious_elements': [],
            'favicon_mismatch': False,
            'login_form_present': False,
            'seo_issues': [],
            'html_quality': {}
        }
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check page title
            title = soup.title.text if soup.title else ""
            analysis['page_title'] = title
            
            # Extract domain from URL for comparison
            domain = urllib.parse.urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            
            # Check for title mismatch with domain (often indicates phishing)
            analysis['title_mismatch'] = main_domain.lower() not in title.lower()
            if analysis['title_mismatch']:
                flags.append("Page title doesn't match domain")
                risk_score += 15
            
            # Check for brand mentions in content
            common_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 
                             'google', 'chase', 'bank', 'netflix', 'instagram',
                             'linkedin', 'outlook', 'gmail', 'office365', 'bitcoin',
                             'wellsfargo', 'bankofamerica', 'citibank', 'dropbox']
            
            # Get full page text
            page_text = soup.get_text().lower()
            
            for brand in common_brands:
                if brand.lower() in page_text and brand not in domain.lower():
                    analysis['brand_mentions'].append(brand)
                    flags.append(f"References to {brand} found, but not in domain")
                    risk_score += 10
                    break  # Only count one brand mention for risk score
            
            # NEW: Count number of brand mentions for additional context
            brand_mention_count = sum(1 for brand in common_brands 
                                     if brand.lower() in page_text and brand not in domain.lower())
            if brand_mention_count > 1:
                flags.append(f"Multiple ({brand_mention_count}) brand references not in domain name")
                risk_score += min(5 * (brand_mention_count - 1), 15)  # Cap at +15 points
            
            # Check for hidden elements (common in phishing)
            hidden_elements = soup.select('[style*="display: none"], [style*="display:none"], [style*="visibility: hidden"]')
            
            # NEW: More comprehensive hidden element detection
            additional_hidden = soup.select('[style*="opacity: 0"], [style*="opacity:0"], [hidden], [aria-hidden="true"]')
            hidden_elements.extend(additional_hidden)
            
            # Check for elements positioned off-screen (common phishing technique)
            offscreen_elements = soup.select('[style*="position: absolute"][style*="left: -"], [style*="position:absolute"][style*="left:-"]')
            hidden_elements.extend(offscreen_elements)
            
            analysis['hidden_elements'] = len(hidden_elements)
            if analysis['hidden_elements'] > 2:  # Allow a couple for legitimate sites
                flags.append(f"Found {analysis['hidden_elements']} hidden elements")
                risk_score += 15
                
                # NEW: Check if hidden elements contain sensitive input fields
                sensitive_hidden = False
                for elem in hidden_elements:
                    inputs = elem.find_all('input')
                    for input_elem in inputs:
                        input_type = input_elem.get('type', '')
                        input_name = input_elem.get('name', '').lower()
                        if input_type == 'password' or any(s in input_name for s in ['pass', 'pwd', 'credential']):
                            sensitive_hidden = True
                            break
                
                if sensitive_hidden:
                    flags.append("Hidden elements contain password fields - highly suspicious")
                    risk_score += 25
            
            # Check for iframes (can be used for clickjacking)
            iframes = soup.find_all('iframe')
            analysis['iframe_count'] = len(iframes)
            if analysis['iframe_count'] > 0:
                flags.append(f"Found {analysis['iframe_count']} iframes")
                risk_score += 5 * min(analysis['iframe_count'], 3)  # Cap at 15 points
                
                # NEW: Check for suspicious iframe sources
                suspicious_iframe = False
                for iframe in iframes:
                    src = iframe.get('src', '')
                    if src:
                        # Check if iframe source is from different domain
                        try:
                            iframe_domain = urllib.parse.urlparse(src).netloc
                            if iframe_domain and iframe_domain != domain:
                                suspicious_iframe = True
                                flags.append(f"Iframe from external domain: {iframe_domain}")
                                break
                        except:
                            pass
                
                if suspicious_iframe:
                    risk_score += 10
            
            # Check for external resources
            external_resources = 0
            resource_domains = set()
            parsed_domain = urllib.parse.urlparse(url).netloc
            for tag in soup.find_all(['script', 'link', 'img', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and src.startswith(('http://', 'https://')):
                    try:
                        resource_domain = urllib.parse.urlparse(src).netloc
                        if resource_domain and resource_domain != parsed_domain:
                            external_resources += 1
                            resource_domains.add(resource_domain)
                    except:
                        pass
            
            analysis['external_resources'] = external_resources
            analysis['resource_domains'] = list(resource_domains)
            
            # NEW: Check resource domain count - high count can be suspicious
            if len(resource_domains) > 10:  # Many external domains can be suspicious
                flags.append(f"High number of external domains: {len(resource_domains)}")
                risk_score += min(20, len(resource_domains))
            
            # Look for suspicious meta elements
            meta_refresh = soup.find('meta', {'http-equiv': 'refresh'})
            if meta_refresh:
                analysis['suspicious_elements'].append('meta-refresh')
                flags.append("Page uses meta refresh (possible redirect)")
                risk_score += 10
                
                # NEW: Check if meta refresh redirects to external domain
                content_attr = meta_refresh.get('content', '')
                if 'url=' in content_attr.lower():
                    redirect_url = content_attr.split('url=', 1)[1].strip()
                    try:
                        redirect_domain = urllib.parse.urlparse(redirect_url).netloc
                        if redirect_domain and redirect_domain != domain:
                            flags.append(f"Meta refresh redirects to external domain: {redirect_domain}")
                            risk_score += 15
                    except:
                        pass
            
            # NEW: Check favicon source domain
            favicon_mismatch = False
            favicon_tags = soup.find_all('link', rel=['icon', 'shortcut icon', 'apple-touch-icon'])
            
            for favicon in favicon_tags:
                href = favicon.get('href', '')
                if href and href.startswith(('http://', 'https://')):
                    try:
                        favicon_domain = urllib.parse.urlparse(href).netloc
                        if favicon_domain and favicon_domain != domain:
                            favicon_mismatch = True
                            flags.append(f"Favicon from different domain: {favicon_domain}")
                            break
                    except:
                        pass
            
            analysis['favicon_mismatch'] = favicon_mismatch
            if favicon_mismatch:
                risk_score += 10
            
            # NEW: Check login form presence
            login_forms = 0
            password_fields = 0
            
            # Find forms with password fields or login-related attributes
            for form in soup.find_all('form'):
                has_password = len(form.find_all('input', {'type': 'password'})) > 0
                form_id = form.get('id', '').lower()
                form_class = form.get('class', [])
                form_class = ' '.join(form_class).lower() if form_class else ''
                form_action = form.get('action', '').lower()
                
                login_indicators = ['login', 'signin', 'sign-in', 'logon', 'auth', 'credential']
                
                if (has_password or 
                    any(ind in form_id for ind in login_indicators) or
                    any(ind in form_class for ind in login_indicators) or
                    any(ind in form_action for ind in login_indicators)):
                    
                    login_forms += 1
                    password_fields += len(form.find_all('input', {'type': 'password'}))
            
            analysis['login_form_present'] = login_forms > 0
            analysis['login_forms_count'] = login_forms
            analysis['password_fields_count'] = password_fields
            
            if login_forms > 0:
                # For login forms, check if they submit to external domain
                external_action = False
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    if action.startswith(('http://', 'https://')):
                        try:
                            action_domain = urllib.parse.urlparse(action).netloc
                            if action_domain and action_domain != domain:
                                external_action = True
                                flags.append(f"Login form submits to external domain: {action_domain}")
                                break
                        except:
                            pass
                
                if external_action:
                    risk_score += 30
                elif password_fields > 0:
                    # Only flag login form as suspicious if not part of main domain (may be legitimate)
                    brand_in_domain = any(brand in domain.lower() for brand in analysis['brand_mentions'])
                    if brand_in_domain:
                        flags.append("Login form present with known brand in URL - potential phishing")
                        risk_score += 15
            
            # NEW: Check for poor HTML quality (often indicates phishing)
            html_quality = {
                'has_doctype': bool(soup.find('html').parent.name == '[document]' if soup.find('html') else False),
                'has_html_tag': bool(soup.find('html')),
                'has_head_tag': bool(soup.find('head')),
                'has_body_tag': bool(soup.find('body')),
                'has_broken_links': False,
                'element_count': len(soup.find_all()),
                'text_to_html_ratio': len(page_text) / max(1, len(content))
            }
            
            # Check for broken links
            broken_links = 0
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if href == '#' or href == '' or href == 'javascript:void(0)':
                    broken_links += 1
            
            html_quality['broken_links_count'] = broken_links
            html_quality['has_broken_links'] = broken_links > 5
            
            analysis['html_quality'] = html_quality
            
            # Score for poor HTML quality
            quality_issues = 0
            if not html_quality['has_doctype']:
                quality_issues += 1
            if not html_quality['has_head_tag'] or not html_quality['has_body_tag']:
                quality_issues += 1
            if html_quality['has_broken_links']:
                quality_issues += 1
            if html_quality['element_count'] < 10:  # Very simple page
                quality_issues += 1
            
            if quality_issues >= 2:
                flags.append(f"Poor HTML quality ({quality_issues} issues detected)")
                risk_score += quality_issues * 5  # 5 points per quality issue
            
            # NEW: Check for SEO elements consistency
            meta_description = soup.find('meta', {'name': 'description'})
            meta_keywords = soup.find('meta', {'name': 'keywords'})
            
            seo_issues = []
            
            # Check if meta description includes domain name
            if meta_description:
                meta_desc_content = meta_description.get('content', '').lower()
                if main_domain.lower() not in meta_desc_content:
                    seo_issues.append("Meta description doesn't match domain")
            
            # Check for keyword stuffing (often in phishing)
            if meta_keywords:
                keywords = meta_keywords.get('content', '').lower()
                keyword_count = len(keywords.split(','))
                if keyword_count > 15:  # Excessive keywords
                    seo_issues.append(f"Keyword stuffing ({keyword_count} keywords)")
            
            if seo_issues:
                analysis['seo_issues'] = seo_issues
                flags.extend(seo_issues)
                risk_score += len(seo_issues) * 5  # 5 points per SEO issue
                
        except Exception as e:
            flags.append(f"HTML analysis error: {str(e)}")
        
        return risk_score, flags, analysis
    
    def _analyze_javascript(self, content: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze JavaScript for suspicious patterns."""
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
            from bs4 import BeautifulSoup
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
    
    def _analyze_forms(self, content: str, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Analyze forms for phishing indicators."""
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
            from bs4 import BeautifulSoup
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
    
    def _check_ssl(self, url: str) -> Tuple[float, List[str], Dict[str, Any]]:
        """Check SSL certificate validity."""
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
            import socket
            import ssl
            import OpenSSL.crypto as crypto
            from datetime import datetime
            
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
            # Don't add risk score for analysis failures
        
        return risk_score, flags, ssl_info

# Update the LayeredPhishingDetector class to include the new layer


class Layer3_MLClassification(DetectionLayer):
    """
    Layer 3: Machine Learning Classification
    - Uses trained ML model to classify URLs
    - Provides confidence scores for phishing probability
    """
    
    def __init__(self):
        super().__init__("ML Classification", weight=1.5)  # Higher weight for ML predictions
        self.model = None
        self.vectorizer = None
        self._load_model()
    
    def _load_model(self):
        """Load ML model and vectorizer."""
        try:
            self.model, self.vectorizer = load_model()
            if self.model is not None and self.vectorizer is not None:
                logger.info("ML model and vectorizer loaded successfully")
            else:
                logger.warning("ML model or vectorizer not loaded")
                self.enabled = False
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            self.enabled = False
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze URL using ML model."""
        results = {
            'layer': self.name,
            'risk_score': 0.0,
            'flags': []
        }
        
        try:
            if not self.model or not self.vectorizer:
                results['flags'].append("ML model not available")
                results['risk_score'] = 0
                return results
            
            # Start timing for inference
            start_time = datetime.now()
            
            # Get ML prediction
            prediction = predict_with_ml(url, self.model, self.vectorizer)
            
            # End timing
            inference_time = (datetime.now() - start_time).total_seconds()
            
            if prediction is None:
                results['flags'].append("ML prediction failed")
                results['risk_score'] = 30
                return results
            
            # Extract information from prediction
            is_phishing = prediction['prediction'] == 'phishing'
            confidence = prediction.get('confidence', 0)
            confidence_scores = prediction.get('confidence_scores', {})
            
            # Add results
            results['ml_prediction'] = prediction['prediction']
            results['confidence_scores'] = confidence_scores
            results['inference_time'] = inference_time
            
            # Set risk score based on phishing probability
            if is_phishing:
                phish_confidence = confidence_scores.get('phishing', confidence)
                # Scale to risk score from 0-100
                results['risk_score'] = min(100, phish_confidence * 100)
                
                # Add flags based on confidence
                if phish_confidence > 0.8:
                    results['flags'].append("High probability of phishing")
                elif phish_confidence > 0.6:
                    results['flags'].append("Medium probability of phishing")
                else:
                    results['flags'].append("Low probability of phishing")
            else:
                # If legitimate, risk score is inverse of legitimate confidence
                legit_confidence = confidence_scores.get('legitimate', 1 - confidence)
                results['risk_score'] = min(100, (1 - legit_confidence) * 80)  # Cap at 80 for negative predictions
            
            # Add model info
            try:
                model_type = "RandomForest"
                if "XGBClassifier" in str(type(self.model)):
                    model_type = "XGBoost"
                
                # Check if model uses GPU
                gpu_accelerated = False
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    if 'tree_method' in params:
                        gpu_accelerated = 'gpu' in params['tree_method']
                
                results['model_info'] = {
                    'type': model_type,
                    'accuracy': 0.8147,  # Placeholder - should come from evaluation
                    'gpu_accelerated': gpu_accelerated
                }
            except:
                # Ignore if model info collection fails
                pass
            
        except Exception as e:
            results['flags'].append(f"ML classification error: {str(e)}")
            results['risk_score'] = 10  # Small default risk for errors
        
        return results



class Layer4_EnsembleDecision(DetectionLayer):
    """
    Layer 4: Ensemble Decision
    - Combines results from previous layers
    - Resolves conflicts between layers
    - Produces weighted risk score
    """
    
    def __init__(self):
        super().__init__("Ensemble Decision")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Combine results from previous layers."""
        results = {
            'layer': self.name,
            'weighted_risk_score': 0.0,
            'layer_scores': {},
            'consensus': None,
            'conflicts': []
        }
        
        try:
            if not context or 'layer_results' not in context:
                results['weighted_risk_score'] = 50
                results['consensus'] = "ERROR"
                results['conflicts'].append("No layer results found")
                return results
            
            layer_results = context['layer_results']
            
            # Calculate weighted risk score
            total_weight = 0
            weighted_score = 0
            layer_votes = {'phishing': 0, 'legitimate': 0, 'unknown': 0}
            
            # Track scores for each layer
            for layer_result in layer_results:
                layer_name = layer_result.get('layer', 'Unknown')
                risk_score = layer_result.get('risk_score', 0)
                weight = layer_result.get('weight', 1.0)
                
                # Add to weighted score
                weighted_score += risk_score * weight
                total_weight += weight
                
                # Record layer score
                results['layer_scores'][layer_name] = risk_score
                
                # Determine layer vote
                if risk_score >= 60:  # High risk
                    layer_votes['phishing'] += 1
                elif risk_score <= 30:  # Low risk
                    layer_votes['legitimate'] += 1
                else:
                    layer_votes['unknown'] += 1
            
            # Calculate final weighted score
            if total_weight > 0:
                results['weighted_risk_score'] = weighted_score / total_weight
            else:
                results['weighted_risk_score'] = 50
            
            # Determine consensus
            if layer_votes['phishing'] > layer_votes['legitimate'] + layer_votes['unknown']:
                results['consensus'] = "PHISHING"
            elif layer_votes['legitimate'] > layer_votes['phishing'] + layer_votes['unknown']:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['phishing'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "LEGITIMATE"
            elif layer_votes['legitimate'] == 0 and layer_votes['unknown'] == 0:
                results['consensus'] = "PHISHING"
            else:
                results['consensus'] = "UNCERTAIN"
            
            # Check for conflicts
            if layer_votes['phishing'] > 0 and layer_votes['legitimate'] > 0:
                results['conflicts'].append("Layers disagree on classification")
            
            # Check for strong ML disagreement
            ml_result = None
            for layer_result in layer_results:
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction == 'phishing' and results['weighted_risk_score'] < 40:
                        results['conflicts'].append("ML says phishing but other layers disagree")
                    elif ml_prediction == 'legitimate' and results['weighted_risk_score'] > 60:
                        results['conflicts'].append("ML says legitimate but other layers disagree")
                    ml_result = layer_result
                    break
            
            # If ML is very confident, increase its influence
            if ml_result and 'confidence_scores' in ml_result:
                ml_confidence = max(ml_result['confidence_scores'].values()) if ml_result['confidence_scores'] else 0
                if ml_confidence > 0.9:  # Very high confidence
                    ml_prediction = ml_result.get('ml_prediction')
                    if ml_prediction == 'phishing':
                        results['weighted_risk_score'] = max(results['weighted_risk_score'], 
                                                            results['weighted_risk_score'] * 1.2)  # Increase by 20%
                    elif ml_prediction == 'legitimate':
                        results['weighted_risk_score'] = min(results['weighted_risk_score'], 
                                                           results['weighted_risk_score'] * 0.8)  # Decrease by 20%
            
        except Exception as e:
            results['weighted_risk_score'] = 50
            results['consensus'] = "ERROR"
            results['conflicts'].append(f"Ensemble error: {str(e)}")
        
        return results



class Layer5_FinalVerdict(DetectionLayer):
    """
    Layer 5: Final Verdict
    - Determines final risk level
    - Provides recommendations
    - Aggregates warnings and details
    """
    
    def __init__(self):
        super().__init__("Final Verdict")
    
    def analyze(self, url: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate final verdict and recommendations."""
        results = {
            'final_verdict': RiskLevel.ERROR,
            'risk_percentage': 50,
            'confidence': 0.0,
            'recommendations': [],
            'summary': {},
            'early_termination': False
        }
        
        try:
            if not context:
                results['final_verdict'] = RiskLevel.ERROR
                results['risk_percentage'] = 50
                results['recommendations'].append("Analysis failed - insufficient data")
                return results
            
            # Check for early termination
            if 'final_result' in context and context['final_result'].get('early_termination', False):
                return context['final_result']
            
            # Get ensemble result
            ensemble_result = context.get('ensemble_result', {})
            risk_score = ensemble_result.get('weighted_risk_score', 50)
            consensus = ensemble_result.get('consensus', 'UNCERTAIN')
            conflicts = ensemble_result.get('conflicts', [])
            
            # Set risk percentage
            results['risk_percentage'] = risk_score
            
            # Determine confidence based on conflicts
            if not conflicts:
                confidence = 0.9  # High confidence if no conflicts
            elif len(conflicts) == 1:
                confidence = 0.7  # Medium confidence with one conflict
            else:
                confidence = 0.5  # Low confidence with multiple conflicts
                
            results['confidence'] = confidence
            
            # Determine final risk level
            if risk_score >= 75:
                results['final_verdict'] = RiskLevel.CRITICAL
            elif risk_score >= 60:
                results['final_verdict'] = RiskLevel.HIGH
            elif risk_score >= 35:
                results['final_verdict'] = RiskLevel.MEDIUM
            elif risk_score >= 15:
                results['final_verdict'] = RiskLevel.LOW
            else:
                results['final_verdict'] = RiskLevel.SAFE
            
            # Generate recommendations based on risk level
            if results['final_verdict'] in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                results['recommendations'].extend([
                    "Do NOT proceed to this website",
                    "Do NOT enter any personal information",
                    "Do NOT download any files from this site"
                ])
            elif results['final_verdict'] == RiskLevel.MEDIUM:
                results['recommendations'].extend([
                    "Proceed with extreme caution",
                    "Verify the website through other channels before sharing information",
                    "Check the URL carefully for typos or unusual characters"
                ])
            elif results['final_verdict'] == RiskLevel.LOW:
                results['recommendations'].extend([
                    "Exercise normal caution",
                    "Verify the website if sharing sensitive information"
                ])
            else:  # SAFE
                results['recommendations'].extend([
                    "Website appears safe",
                    "Follow normal security practices"
                ])
            
            # Add any specific warnings from layers
            layer_flags = []
            for layer_result in context.get('layer_results', []):
                layer_flags.extend(layer_result.get('flags', []))
            
            if layer_flags:
                results['summary']['warnings'] = layer_flags[:5]  # Include top 5 warnings
                
            # If ML prediction exists, add to summary
            for layer_result in context.get('layer_results', []):
                if layer_result.get('layer') == 'ML Classification':
                    ml_prediction = layer_result.get('ml_prediction')
                    if ml_prediction:
                        results['summary']['ml_prediction'] = ml_prediction
                    break
            
        except Exception as e:
            results['final_verdict'] = RiskLevel.ERROR
            results['risk_percentage'] = 50
            results['recommendations'].append(f"Analysis error: {str(e)}")
        
        return results



class LayeredPhishingDetector:
    """
    Main class implementing the layered phishing detection system.
    """
    
    def __init__(self):
        self.layers = [
            Layer1_BasicValidation(),
            Layer2_FeatureAnalysis(),
            Layer2_ContentAnalysis(),
            Layer3_MLClassification(),
            Layer4_EnsembleDecision(),
            Layer5_FinalVerdict()
        ]
        
        logger.info(f"Initialized {len(self.layers)} detection layers")
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL through all detection layers.
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict[str, Any]: Comprehensive analysis results
        """
        analysis_results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'layer_results': [],
            'ensemble_result': {},
            'final_result': {},
            'processing_time': 0.0
        }
        
        start_time = datetime.now()
        
        try:
            # Pass URL through each layer
            context = {}
            
            for i, layer in enumerate(self.layers):
                if not layer.enabled:
                    logger.warning(f"Layer {layer.name} is disabled, skipping")
                    continue
                
                logger.info(f"Processing layer {i+1}: {layer.name}")
                
                # Special handling for ensemble and final layers
                if isinstance(layer, Layer4_EnsembleDecision):
                    context['layer_results'] = analysis_results['layer_results']
                    layer_result = layer.analyze(url, context)
                    analysis_results['ensemble_result'] = layer_result
                
                elif isinstance(layer, Layer5_FinalVerdict):
                    context['ensemble_result'] = analysis_results['ensemble_result']
                    context['layer_results'] = analysis_results['layer_results']
                    layer_result = layer.analyze(url, context)
                    analysis_results['final_result'] = layer_result
                
                else:
                    layer_result = layer.analyze(url, context)
                    layer_result['weight'] = layer.weight
                    analysis_results['layer_results'].append(layer_result)
                
                # Early termination for critical issues in Layer 1
                if (isinstance(layer, Layer1_BasicValidation) and 
                    not layer_result.get('passed', True) and 
                    layer_result.get('risk_score', 0) > 80):
                    
                    logger.warning("Critical issues detected in Layer 1, terminating analysis")
                    analysis_results['final_result'] = {
                        'final_verdict': RiskLevel.CRITICAL,
                        'risk_percentage': layer_result['risk_score'],
                        'confidence': 0.9,
                        'early_termination': True,
                        'recommendations': [
                            "🚨 Critical security threat detected",
                            "🚨 DO NOT proceed with this URL"
                        ]
                    }
                    break
        
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            analysis_results['error'] = str(e)
            analysis_results['final_result'] = {
                'final_verdict': RiskLevel.ERROR,
                'error': str(e)
            }
        
        # Calculate processing time
        end_time = datetime.now()
        analysis_results['processing_time'] = (end_time - start_time).total_seconds()
        
        return analysis_results
    
    def get_quick_verdict(self, url: str) -> str:
        """Get a quick verdict for simple use cases."""
        results = self.analyze_url(url)
        final_result = results.get('final_result', {})
        verdict = final_result.get('final_verdict', RiskLevel.ERROR)
        
        if isinstance(verdict, RiskLevel):
            return verdict.value
        return str(verdict)

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract features from a URL for phishing detection.
    
    Address Bar-based Features:
    - has_ip_address: Boolean indicating if the hostname is an IPv4 address
    - url_length: Classification based on URL length:
        - "Legitimate" if length < 54
        - "Suspicious" if length 54-75 (inclusive)  
        - "Phishing" if length > 75
    - is_shortened: Boolean indicating if the URL uses a known shortening service
    - double_slash_redirect: Boolean indicating if "//" appears after position 7
    - has_dash_in_domain: Boolean indicating if the domain contains a dash "-"
    - subdomain_level: Classification based on subdomain count:
        - "Legitimate" if subdomain count <= 1
        - "Suspicious" if subdomain count == 2
        - "Phishing" if subdomain count > 2
    - https_token_in_domain: Boolean indicating if "https" appears in domain name
    
    Domain-based Features:
    - domain_age: Classification based on domain age via WHOIS:
        - "Legitimate" if age >= 6 months
        - "Phishing" if age < 6 months or unavailable
    - domain_registration_length: Classification based on domain expiry:
        - "Legitimate" if expires > 1 year from now
        - "Phishing" if expires <= 1 year or unavailable
    - dns_record: Boolean indicating if DNS record exists for domain
    - alexa_rank: Classification based on website popularity:
        - "Legitimate" if rank < 100,000
        - "Suspicious" if rank 100,000-999,999
        - "Phishing" if rank > 999,999 or not found
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        Dict[str, Any]: A dictionary containing extracted features
    """
    features = {}
    
    try:
        # Parse the URL to extract components
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        # Remove port number if present (e.g., "192.168.1.1:8080" -> "192.168.1.1")
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Check if hostname is an IPv4 address using regex
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features["has_ip_address"] = bool(re.match(ipv4_pattern, hostname))
        
        # Classify URL based on length
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:  # url_length > 75
            features["url_length"] = "Phishing"
        
        # Check if URL uses a known shortening service
        known_shorteners = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", 
            "is.gd", "buff.ly", "rebrand.ly", "short.link", "tiny.cc",
            "url.ie", "v.gd", "lnkd.in", "youtu.be", "amzn.to"
        ]
        
        # Extract domain (remove www. prefix if present)
        domain = hostname.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        features["is_shortened"] = domain in known_shorteners
        
        # 1. Check for double slash redirection (// after position 7)
        last_double_slash_pos = url.rfind('//')
        features["double_slash_redirect"] = last_double_slash_pos > 7
        
        # Use tldextract for accurate domain parsing
        extracted = tldextract.extract(url)
        full_domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        
        # 2. Check for dash in domain name (check both domain and subdomain)
        has_dash_domain = '-' in extracted.domain
        has_dash_subdomain = '-' in extracted.subdomain if extracted.subdomain else False
        features["has_dash_in_domain"] = has_dash_domain or has_dash_subdomain
        
        # 3. Subdomain count classification
        # Count dots in subdomain part (tldextract automatically excludes www, domain, and suffix)
        subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
        # Remove empty parts and 'www' if present
        subdomain_parts = [part for part in subdomain_parts if part and part.lower() != 'www']
        subdomain_count = len(subdomain_parts)
        
        if subdomain_count <= 1:
            features["subdomain_level"] = "Legitimate"
        elif subdomain_count == 2:
            features["subdomain_level"] = "Suspicious"
        else:  # subdomain_count > 2
            features["subdomain_level"] = "Phishing"
        
        # 4. Check for "https" token in domain name (check subdomain + domain + suffix)
        # Combine all parts except the protocol
        all_domain_parts = []
        if extracted.subdomain:
            all_domain_parts.append(extracted.subdomain)
        if extracted.domain:
            all_domain_parts.append(extracted.domain)
        if extracted.suffix:
            all_domain_parts.append(extracted.suffix)
        
        complete_domain = '.'.join(all_domain_parts).lower()
        features["https_token_in_domain"] = 'https' in complete_domain
        
        # =================== DOMAIN-BASED FEATURES ===================
        
        # Get the main domain for WHOIS and DNS checks
        main_domain = full_domain if full_domain else f"{extracted.domain}.{extracted.suffix}"
        
        # 5. Domain Age using WHOIS
        try:
            domain_info = whois.whois(main_domain)
            creation_date = domain_info.creation_date
            
            if creation_date:
                # Handle case where creation_date might be a list
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Calculate domain age
                domain_age_days = (datetime.now() - creation_date).days
                domain_age_months = domain_age_days / 30.44  # Average days per month
                
                if domain_age_months >= 6:
                    features["domain_age"] = "Legitimate"
                else:
                    features["domain_age"] = "Phishing"
            else:
                features["domain_age"] = "Phishing"  # No creation date found
                
        except Exception as e:
            features["domain_age"] = "Phishing"  # WHOIS lookup failed
        
        # 6. Domain Registration Length using WHOIS
        try:
            if 'domain_info' in locals() and domain_info.expiration_date:
                expiration_date = domain_info.expiration_date
                
                # Handle case where expiration_date might be a list
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                # Calculate time until expiration
                days_until_expiry = (expiration_date - datetime.now()).days
                
                if days_until_expiry <= 365:  # 1 year or less
                    features["domain_registration_length"] = "Phishing"
                else:
                    features["domain_registration_length"] = "Legitimate"
            else:
                features["domain_registration_length"] = "Phishing"  # No expiration date
                
        except Exception as e:
            features["domain_registration_length"] = "Phishing"  # Failed to get expiration
        
        # 7. DNS Record Exists
        try:
            socket.gethostbyname(main_domain)
            features["dns_record"] = True
        except socket.gaierror:
            features["dns_record"] = False
        except Exception as e:
            features["dns_record"] = False
        
        # 8. Alexa Rank (using dummy implementation for now)
        # In a real implementation, you would use an API like Alexa or similar ranking service
        try:
            # For demonstration, we'll use domain length as a proxy
            # In reality, you'd call an API like: alexa_rank = get_alexa_rank(main_domain)
            domain_length = len(main_domain)
            
            # Dummy logic: shorter domains tend to be more popular
            if domain_length <= 10:
                dummy_rank = 50000  # High ranking (legitimate)
            elif domain_length <= 15:
                dummy_rank = 150000  # Medium ranking
            else:
                dummy_rank = 999999  # Low ranking
            
            if dummy_rank < 100000:
                features["alexa_rank"] = "Legitimate"
            elif dummy_rank <= 999999:
                features["alexa_rank"] = "Suspicious"
            else:
                features["alexa_rank"] = "Phishing"
                
        except Exception as e:
            features["alexa_rank"] = "Phishing"  # No rank found
        
    except Exception as e:
        # If URL parsing fails, set default values for all features
        features["has_ip_address"] = False
        features["is_shortened"] = False
        features["double_slash_redirect"] = False
        features["has_dash_in_domain"] = False
        features["subdomain_level"] = "Legitimate"
        features["https_token_in_domain"] = False
        
        # Domain-based features defaults
        features["domain_age"] = "Phishing"
        features["domain_registration_length"] = "Phishing"
        features["dns_record"] = False
        features["alexa_rank"] = "Phishing"
        
        # Still classify URL length even if parsing fails
        url_length = len(url)
        if url_length < 54:
            features["url_length"] = "Legitimate"
        elif 54 <= url_length <= 75:
            features["url_length"] = "Suspicious"
        else:
            features["url_length"] = "Phishing"
    
    # TODO: Implement additional feature extraction logic
    # Features might include:
    # - URL length
    # - Number of dots, slashes, special characters
    # - Presence of suspicious keywords
    # - Domain-based features
    # - HTTPS usage
    # - etc.
    
    return features


def check_url(url: str) -> str:
    """
    Simple function to quickly check if a URL is suspicious.
    
    Args:
        url (str): URL to check
        
    Returns:
        str: Simple assessment ("SAFE", "SUSPICIOUS", "DANGEROUS")
    """
    try:
        features = extract_features(url)
        
        # Count high-risk indicators
        danger_count = 0
        if features['has_ip_address']:
            danger_count += 1
        if features['url_length'] == 'Phishing':
            danger_count += 1
        if features['double_slash_redirect']:
            danger_count += 1
        if features['https_token_in_domain']:
            danger_count += 1
        if features['domain_age'] == 'Phishing':
            danger_count += 1
        if not features['dns_record']:
            danger_count += 1
            
        # Count medium-risk indicators
        suspect_count = 0
        if features['is_shortened']:
            suspect_count += 1
        if features['has_dash_in_domain']:
            suspect_count += 1
        if features['subdomain_level'] in ['Suspicious', 'Phishing']:
            suspect_count += 1
        if features['url_length'] == 'Suspicious':
            suspect_count += 1
            
        # Make assessment
        if danger_count >= 2:
            return "DANGEROUS"
        elif danger_count >= 1 or suspect_count >= 3:
            return "SUSPICIOUS"
        elif suspect_count >= 1:
            return "CAUTION"
        else:
            return "SAFE"
            
    except Exception:
        return "ERROR"


def load_model() -> Tuple[Any, Any]:
    """
    Load a pre-trained machine learning model and vectorizer for phishing detection.
    
    Returns:
        Tuple[Any, Any]: The loaded ML model and vectorizer, or (None, None) if loading fails
    """
    try:
        models_dir = os.path.join(os.path.dirname(__file__), 'models')
        model_path = os.path.join(models_dir, 'phishing_classifier.pkl')
        vectorizer_path = os.path.join(models_dir, 'tfidf_vectorizer.pkl')
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            model = joblib.load(model_path)
            vectorizer = joblib.load(vectorizer_path)
            logger.info("Successfully loaded ML model and vectorizer")
            
            # Load evaluation results if available
            results_path = os.path.join(models_dir, 'evaluation_results.json')
            if os.path.exists(results_path):
                with open(results_path, 'r') as f:
                    results = json.load(f)
                logger.info(f"Model accuracy: {results['accuracy']:.4f}")
            
            return model, vectorizer
        else:
            logger.warning("Model or vectorizer files not found")
            return None, None
    except Exception as e:
        logger.error(f"Could not load model: {e}")
        return None, None


def predict_with_ml(url: str, model: Any, vectorizer: Any) -> Dict[str, Any]:
    """
    Use the trained ML model to predict if a URL is phishing.
    
    Args:
        url (str): URL to analyze
        model: Trained ML model
        vectorizer: Fitted TF-IDF vectorizer
        
    Returns:
        Dict[str, Any]: Prediction results with confidence scores
    """
    try:
        # Transform URL using the same vectorizer used in training
        url_vec = vectorizer.transform([url])
        
        # Get prediction and confidence
        prediction = model.predict(url_vec)[0]
        confidence_scores = model.predict_proba(url_vec)[0]
        
        return {
            'prediction': 'phishing' if prediction == 1 else 'legitimate',
            'confidence': float(max(confidence_scores)),
            'confidence_scores': {
                'legitimate': float(confidence_scores[0]),
                'phishing': float(confidence_scores[1])
            },
            'method': 'machine_learning'
        }
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        return None


def features_to_vector(features: Dict[str, Any]) -> list:
    """Convert feature dictionary to numerical vector for ML models."""
    vector = []
    
    # Boolean features (0 or 1)
    vector.append(1 if features['has_ip_address'] else 0)
    vector.append(1 if features['is_shortened'] else 0)
    vector.append(1 if features['double_slash_redirect'] else 0)
    vector.append(1 if features['has_dash_in_domain'] else 0)
    vector.append(1 if features['https_token_in_domain'] else 0)
    vector.append(1 if features['dns_record'] else 0)
    
    # Categorical features (convert to numerical)
    url_length_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(url_length_map.get(features['url_length'], 2))
    
    subdomain_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(subdomain_map.get(features['subdomain_level'], 2))
    
    domain_age_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(domain_age_map.get(features['domain_age'], 1))
    
    reg_length_map = {'Legitimate': 0, 'Phishing': 1}
    vector.append(reg_length_map.get(features['domain_registration_length'], 1))
    
    alexa_map = {'Legitimate': 0, 'Suspicious': 1, 'Phishing': 2}
    vector.append(alexa_map.get(features['alexa_rank'], 2))
    
    return vector


def rule_based_classification(features: Dict[str, Any]) -> Dict[str, Any]:
    """Simple rule-based classification as fallback."""
    phishing_score = 0
    
    # High risk indicators
    if features['has_ip_address']:
        phishing_score += 2
    if features['url_length'] == 'Phishing':
        phishing_score += 2
    if features['double_slash_redirect']:
        phishing_score += 2
    if features['https_token_in_domain']:
        phishing_score += 2
    if features['domain_age'] == 'Phishing':
        phishing_score += 2
    if not features['dns_record']:
        phishing_score += 2
    
    # Medium risk indicators
    if features['is_shortened']:
        phishing_score += 1
    if features['has_dash_in_domain']:
        phishing_score += 1
    if features['subdomain_level'] == 'Phishing':
        phishing_score += 1
    elif features['subdomain_level'] == 'Suspicious':
        phishing_score += 0.5
    if features['url_length'] == 'Suspicious':
        phishing_score += 0.5
    
    # Classification based on score
    if phishing_score >= 4:
        prediction = 'phishing'
        confidence = 0.9
    elif phishing_score >= 2:
        prediction = 'phishing'
        confidence = 0.7
    else:
        prediction = 'legitimate'
        confidence = 0.6
    
    return {
        'prediction': prediction,
        'confidence': confidence,
        'phishing_score': phishing_score,
        'method': 'rule_based'
    }


def classify_url(features: Dict[str, Any] = None, url: str = None, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Classify a URL as phishing or legitimate using both ML and rule-based methods.
    
    Args:
        features (Dict[str, Any]): Dictionary of extracted features (optional)
        url (str): URL to classify (required for ML method)
        model: Pre-trained ML model (optional)
        vectorizer: Fitted vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Classification result including prediction and confidence
    """
    try:
        # Try ML prediction first if model and URL are available
        if model is not None and vectorizer is not None and url is not None:
            ml_result = predict_with_ml(url, model, vectorizer)
            if ml_result is not None:
                # Also get rule-based prediction for comparison
                if features is None:
                    features = extract_features(url)
                rule_result = rule_based_classification(features)
                
                # Combine results
                ml_result['rule_based_prediction'] = rule_result['prediction']
                ml_result['rule_based_score'] = rule_result['phishing_score']
                ml_result['features'] = features
                
                return ml_result
        
        # Fall back to rule-based classification
        if features is None and url is not None:
            features = extract_features(url)
        elif features is None:
            raise ValueError("Either features or url must be provided")
            
        return rule_based_classification(features)
        
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        # Return safe default
        return {
            'prediction': 'error',
            'confidence': 0.0,
            'method': 'error',
            'error': str(e)
        }


def check_url_enhanced(url: str, model=None, vectorizer=None) -> Dict[str, Any]:
    """
    Enhanced URL checking with detailed analysis.
    
    Args:
        url (str): URL to check
        model: ML model (optional)
        vectorizer: Vectorizer (optional)
        
    Returns:
        Dict[str, Any]: Detailed analysis results
    """
    try:
        # Extract features
        features = extract_features(url)
        
        # Get classification
        classification = classify_url(features=features, url=url, model=model, vectorizer=vectorizer)
        
        # Calculate risk assessment
        risk_level = "LOW"
        if classification['prediction'] == 'phishing':
            if classification['confidence'] > 0.8:
                risk_level = "HIGH"
            elif classification['confidence'] > 0.6:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW-MEDIUM"
        
        return {
            'url': url,
            'risk_level': risk_level,
            'classification': classification,
            'features': features,
            'recommendations': get_recommendations(features, classification)
        }
        
    except Exception as e:
        logger.error(f"Enhanced URL check failed: {e}")
        return {
            'url': url,
            'risk_level': "ERROR",
            'error': str(e)
        }


def get_recommendations(features: Dict[str, Any], classification: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    if classification['prediction'] == 'phishing':
        recommendations.append("⚠️  DO NOT enter personal information on this site")
        recommendations.append("⚠️  DO NOT download files from this site")
        
    if features.get('has_ip_address'):
        recommendations.append("🔍 URL uses IP address instead of domain name")
    
    if features.get('is_shortened'):
        recommendations.append("🔍 Shortened URL - check the actual destination")
    
    if features.get('https_token_in_domain'):
        recommendations.append("🔍 Domain contains 'https' - potential impersonation")
    
    if not features.get('dns_record'):
        recommendations.append("🔍 Domain has no DNS record - highly suspicious")
    
    if classification['prediction'] == 'legitimate':
        recommendations.append("✅ URL appears to be legitimate")
        recommendations.append("💡 Still verify the site's authenticity through official channels")
    
    return recommendations


def main() -> None:
    """
    Main function demonstrating the layered phishing detection system with GPU support.
    """
    print("🛡️  Layered Phishing Detection System v3.0 - GPU Accelerated")
    print("="*70)
    
    # Initialize the layered detector
    detector = LayeredPhishingDetector()
    
    # Check GPU status
    try:
        import xgboost as xgb
        gpu_count = xgb.gpu.get_gpu_count()
        if gpu_count > 0:
            print(f"🚀 GPU acceleration available: {gpu_count} device(s)")
        else:
            print("🔄 Running on CPU")
    except:
        print("🔄 Running on CPU")
    
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://github.com", 
        "http://192.168.1.1/login",
        "https://bit.ly/3abc123",
        "https://https-paypal-security.suspicious-bank.com/login//redirect.php",
        "smilesvoegol.servebbs.org/voegol.php",
        "https://amazon-security-verification-account-suspended-click-here-now.malicious-site.net/update",
    ]
    
    # Performance summary
    total_processing_time = 0
    for i, url in enumerate(test_urls, 1):
        print(f"\n{'='*80}")
        print(f"🌐 Test {i}: {url}")
        print(f"📏 Length: {len(url)} characters")
        print("-" * 80)
        
        # Analyze URL through all layers
        analysis = detector.analyze_url(url)
        total_processing_time += analysis['processing_time']
        
        # Display results
        final_result = analysis.get('final_result', {})
        
        if 'error' not in analysis:
            verdict = final_result.get('final_verdict', RiskLevel.ERROR)
            risk_pct = final_result.get('risk_percentage', 0)
            confidence = final_result.get('confidence', 0)
            
            print(f"🎯 FINAL VERDICT: {verdict.value if isinstance(verdict, RiskLevel) else verdict}")
            print(f"📊 Risk Level: {risk_pct:.1f}%")
            print(f"🎪 Confidence: {confidence:.3f}")
            print(f"⏱️  Processing Time: {analysis['processing_time']:.3f}s")
            
            # Show ML layer performance info
            for layer_result in analysis['layer_results']:
                if layer_result.get('layer') == 'ML Classification':
                    model_info = layer_result.get('model_info', {})
                    inference_time = layer_result.get('inference_time', 0)
                    print(f"🤖 ML Model: {model_info.get('type', 'Unknown')} "
                          f"({'GPU' if model_info.get('gpu_accelerated', False) else 'CPU'}) "
                          f"Accuracy: {model_info.get('accuracy', 'N/A')}, "
                          f"Inference Time: {inference_time:.3f}s")