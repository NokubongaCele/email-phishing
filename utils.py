import os
import re
import base64
import hashlib
import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def sanitize_input(text):
    """Sanitize user input to prevent XSS attacks"""
    if not text:
        return ""
    # Replace potentially dangerous characters
    sanitized = re.sub(r'[<>"\'&]', '', text)
    return sanitized

def get_email_headers(email_message):
    """Extract important headers from an email message"""
    headers = {}
    if email_message:
        for header in ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Reply-To']:
            if header in email_message:
                headers[header] = email_message[header]
    return headers

def extract_links_from_html(html_content):
    """Extract all links from HTML content"""
    if not html_content:
        return []
    
    # Find all href attributes in anchor tags
    href_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1'
    links = re.findall(href_pattern, html_content)
    
    # Extract just the URLs
    urls = [link[1] for link in links]
    return urls

def generate_report_id():
    """Generate a unique ID for an analysis report"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    random_component = base64.b64encode(os.urandom(6)).decode('utf-8').replace('/', '_').replace('+', '-')
    return f"report_{timestamp}_{random_component}"

def calculate_risk_score(features):
    """Calculate a normalized risk score from features"""
    if not features or not isinstance(features, list):
        return 0
    
    # Assign weights to different features based on their importance in phishing detection
    weights = [
        1.5,  # contains_urgent_words
        1.0,  # contains_finance_words
        1.2,  # contains_security_words
        1.3,  # num_urls
        2.0,  # num_urls_mismatched_text
        0.7,  # has_html
        0.5,  # has_attachments
        1.8,  # has_common_phishing_phrases
        0.3,  # email_length
        0.8,  # num_misspellings
        1.7,  # contains_ip_urls
        1.4,  # has_suspicious_sender
        1.9,  # request_for_credentials
        1.6,  # email_contains_javascript
        0.9   # link_domain_age_fake
    ]
    
    # Calculate weighted sum
    weighted_sum = sum(feature * weight for feature, weight in zip(features, weights))
    
    # Normalize to 0-100 scale
    max_possible_score = sum(weight for weight in weights)
    normalized_score = (weighted_sum / max_possible_score) * 100
    
    return min(round(normalized_score, 1), 100)  # Cap at 100

def categorize_risk(score):
    """Categorize risk based on score"""
    if score >= 75:
        return "High", "danger"
    elif score >= 50:
        return "Medium", "warning"
    elif score >= 25:
        return "Low", "info"
    else:
        return "Very Low", "success"
