import re
import numpy as np
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from email import parser
import logging
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Download NLTK resources if not already done
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

# Define phishing related keywords
PHISHING_KEYWORDS = [
    'urgent', 'verify', 'account', 'password', 'update', 'bank', 'security', 
    'alert', 'suspend', 'login', 'click', 'confirm', 'validate', 'immediately',
    'paypal', 'credit', 'debit', 'ssn', 'social security', 'limited time',
    'offer', 'prize', 'winner', 'lottery', 'inheritance', 'million', 'dollars',
    'fraud', 'secure', 'unauthorised', 'unauthorized', 'access', 'unusual',
    'activity', 'breach', 'verify', 'verification', 'restricted', 'terminate',
    'expire', 'reset', 'cryptocurrency', 'bitcoin'
]

# Define suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^/\s]*)*',  # URLs
    r'(?:https?://)?(?:www\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^/\s]*)*'  # URLs without protocol
]

# Feature names for readability
FEATURE_NAMES = [
    'contains_urgent_words', 
    'contains_finance_words',
    'contains_security_words',
    'num_urls', 
    'num_urls_mismatched_text',
    'has_html', 
    'has_attachments',
    'has_common_phishing_phrases',
    'email_length',
    'num_misspellings',
    'contains_ip_urls',
    'has_suspicious_sender',
    'request_for_credentials',
    'email_contains_javascript',
    'link_domain_age_fake'  # Always set this to 1 since we can't check domain age in real-time
]

def extract_features(email_content):
    """
    Extract features from email content for phishing detection
    
    Args:
        email_content (str): Raw email content
        
    Returns:
        tuple: (features, important_features)
            - features (list): Numerical features for model input
            - important_features (dict): Human-readable features for explanation
    """
    try:
        # Try to parse as email
        email_message = parser.Parser().parsestr(email_content)
        
        # If can't parse headers properly, treat as just the body
        if not email_message['From'] and not email_message['To'] and not email_message['Subject']:
            email_body = email_content
            email_headers = {}
        else:
            # Extract headers
            email_headers = {k: v for k, v in email_message.items()}
            
            # Extract body
            if email_message.is_multipart():
                email_body = ""
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain" or content_type == "text/html":
                        try:
                            payload = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                            email_body += payload
                        except:
                            pass
            else:
                try:
                    email_body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
                except:
                    email_body = email_message.get_payload()
    except:
        # If parsing fails, assume the input is just the email body
        email_body = email_content
        email_headers = {}
    
    # Preprocessing
    lowercase_body = email_body.lower()
    
    # 1. Check for urgent words
    urgent_words = ['urgent', 'immediately', 'alert', 'attention', 'important', 'critical']
    contains_urgent_words = any(word in lowercase_body for word in urgent_words)
    
    # 2. Check for finance-related words
    finance_words = ['bank', 'account', 'credit', 'debit', 'payment', 'money', 'transfer', 'financial']
    contains_finance_words = any(word in lowercase_body for word in finance_words)
    
    # 3. Check for security-related words
    security_words = ['password', 'login', 'verify', 'secure', 'security', 'update', 'confirm']
    contains_security_words = any(word in lowercase_body for word in security_words)
    
    # 4. Count URLs in the email
    urls = []
    for pattern in SUSPICIOUS_URL_PATTERNS:
        urls.extend(re.findall(pattern, email_body))
    num_urls = len(urls)
    
    # 5. Check for URL text vs. href mismatches (common in phishing)
    href_pattern = r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1'
    href_urls = re.findall(href_pattern, email_body)
    num_urls_mismatched_text = 0
    
    # Simple heuristic for detecting URL text/href mismatches
    link_text_pattern = r'<a\s+(?:[^>]*?\s+)?href=["\'](.*?)["\'](?:[^>]*?)>(.*?)<\/a>'
    for match in re.finditer(link_text_pattern, email_body, re.IGNORECASE | re.DOTALL):
        href = match.group(1)
        text = match.group(2)
        
        # Remove HTML tags from link text
        clean_text = re.sub(r'<[^>]+>', '', text)
        
        # Check if text looks like a URL but doesn't match href
        if (re.search(r'https?://\S+', clean_text) or 
            re.search(r'www\.\S+', clean_text) or 
            re.search(r'\S+\.(com|org|net|edu|gov|co|io)\S*', clean_text)):
            
            # Try to normalize URLs for comparison
            try:
                href_domain = urllib.parse.urlparse(href).netloc
                if href_domain and href_domain not in clean_text:
                    num_urls_mismatched_text += 1
            except:
                # If URL parsing fails, consider it suspicious
                num_urls_mismatched_text += 1
    
    # 6. Check if email contains HTML
    has_html = 1 if re.search(r'<html|<body|<div|<span|<table|<a\s+href', email_body, re.IGNORECASE) else 0
    
    # 7. Check for attachments
    has_attachments = 0
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_disposition() == 'attachment':
                has_attachments = 1
                break
    
    # 8. Check for common phishing phrases
    common_phishing_phrases = [
        'verify your account', 
        'update your information',
        'confirm your details', 
        'unusual activity',
        'suspicious activity',
        'click here to',
        'your account will be suspended',
        'won a prize',
        'claim your reward',
        'access will be disabled'
    ]
    has_common_phishing_phrases = any(phrase in lowercase_body for phrase in common_phishing_phrases)
    
    # 9. Email length (normalized)
    email_length = min(len(email_body) / 5000, 1.0)  # Normalize to 0-1 range
    
    # 10. Check for potential misspellings
    words = re.findall(r'\b[a-zA-Z]{3,15}\b', email_body)
    # This is a simple heuristic - not a comprehensive spell check
    misspelling_patterns = [
        r'[a-z]{2,}[0-9]+[a-z]*',         # Words with numbers mixed in
        r'([a-z])\1{2,}',                 # Characters repeated more than twice
        r'[aeiou]{4,}',                   # Too many consecutive vowels
        r'[bcdfghjklmnpqrstvwxyz]{5,}'    # Too many consecutive consonants
    ]
    num_misspellings = 0
    for word in words:
        if any(re.search(pattern, word.lower()) for pattern in misspelling_patterns):
            num_misspellings += 1
    num_misspellings = min(num_misspellings / 10, 1.0)  # Normalize to 0-1 range
    
    # 11. Check for IP-based URLs
    ip_url_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    contains_ip_urls = 1 if re.search(ip_url_pattern, email_body) else 0
    
    # 12. Check for suspicious sender
    has_suspicious_sender = 0
    if 'From' in email_headers:
        sender = email_headers['From'].lower()
        suspicious_patterns = [
            r'@.*\..*\.[a-z]{2,}',        # Multiple subdomain levels
            r'@.*[0-9]{4,}',              # Numbers in domain
            r'@(?!gmail|yahoo|hotmail|outlook|aol|icloud|protonmail|mail)',  # Uncommon mail providers
            r'@.*\.(ru|cn|top|xyz|tk|ml|ga|cf)',  # Suspicious TLDs
        ]
        if any(re.search(pattern, sender) for pattern in suspicious_patterns):
            has_suspicious_sender = 1
    
    # 13. Check for requests for credentials
    credential_patterns = [
        r'enter.*password',
        r'update.*credentials',
        r'confirm.*account details',
        r'verify.*identity',
        r'login.*details',
        r'your.*pin',
        r'security.*code'
    ]
    request_for_credentials = any(re.search(pattern, lowercase_body) for pattern in credential_patterns)
    
    # 14. Email contains JavaScript
    email_contains_javascript = 1 if re.search(r'<script|javascript:', email_body, re.IGNORECASE) else 0
    
    # 15. Link domain age (since we can't check this in real-time, we'll use a placeholder)
    # In a real-world scenario, this would call an API to check domain registration age
    link_domain_age_fake = 1  # Default to suspicious (short age)
    
    # Combine features into a vector
    features = [
        int(contains_urgent_words),
        int(contains_finance_words),
        int(contains_security_words),
        min(num_urls / 10, 1.0),  # Normalize number of URLs
        min(num_urls_mismatched_text / 5, 1.0),  # Normalize mismatched URLs
        has_html,
        has_attachments,
        int(has_common_phishing_phrases),
        email_length,
        num_misspellings,
        contains_ip_urls,
        has_suspicious_sender,
        int(request_for_credentials),
        email_contains_javascript,
        link_domain_age_fake
    ]
    
    # Create a human-readable dictionary of important features for explanation
    important_features = {}
    
    for i, (feature_name, feature_value) in enumerate(zip(FEATURE_NAMES, features)):
        important_features[feature_name] = feature_value
    
    # Add additional human-readable information
    important_features['urls_found'] = urls[:10]  # Limit to first 10 URLs
    
    if urls:
        important_features['main_url_domain'] = extract_domain(urls[0])
    else:
        important_features['main_url_domain'] = None
    
    # Extract keywords that contributed to the phishing classification
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in lowercase_body:
            found_keywords.append(keyword)
    
    important_features['suspicious_keywords'] = found_keywords[:15]  # Limit to top 15
    
    return features, important_features

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.netloc
    except:
        return url
