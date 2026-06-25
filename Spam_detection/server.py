import http.server
import socketserver
import json
import urllib.request
import urllib.parse
import os
import re
import math
import sqlite3
import hashlib
import secrets
from collections import Counter
from http import cookies

# Set target directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

# Set target directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEIGHTS_PATH = os.path.join(BASE_DIR, "model_weights.json")

# Simple helper to load environment variables from .env
def load_env():
    env = {}
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        env[parts[0].strip()] = parts[1].strip()
    return env

# Global configurations
env_vars = load_env()
PORT = int(env_vars.get("PORT", 8000))
GOOGLE_API_KEY = env_vars.get("GOOGLE_API_KEY", "").strip()

# Check and load model weights
model_weights = None
if os.path.exists(WEIGHTS_PATH):
    try:
        with open(WEIGHTS_PATH, "r", encoding="utf-8") as f:
            model_weights = json.load(f)
        print("Successfully loaded model weights from model_weights.json.")
    except Exception as e:
        print(f"Error loading model weights: {e}")
else:
    print("Warning: model_weights.json not found! Please run train_model.py first to create it.")

# 1. Clean Text Preprocessor (Identical NLP logic to Python trainer)
def clean_text(text):
    if not model_weights:
        return []
    # Lowercase
    text = text.lower()
    # Replace non-alphanumeric characters with space
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    # Split by whitespace
    tokens = text.split()
    # Filter stopwords and short tokens
    stopwords = set(model_weights.get("stopwords", []))
    cleaned = [t for t in tokens if t not in stopwords and (len(t) >= 2 or t.isdigit())]
    return cleaned

# 2. Text Naive Bayes Inference
def classify_text(text):
    if not model_weights:
        return {"error": "Model weights are not loaded. Run train_model.py."}
    
    tokens = clean_text(text)
    
    prior_spam = model_weights["prior_spam"]
    prior_ham = model_weights["prior_ham"]
    vocab_size = model_weights["vocab_size"]
    spam_total_words = model_weights["spam_total_words"]
    ham_total_words = model_weights["ham_total_words"]
    
    # Prior log probabilities
    log_spam = math.log(prior_spam)
    log_ham = math.log(prior_ham)
    
    matched_tokens = []
    
    for token in tokens:
        has_spam = token in model_weights["spam_word_probs"]
        has_ham = token in model_weights["ham_word_probs"]
        
        if has_spam or has_ham:
            p_spam = model_weights["spam_word_probs"].get(token, 1 / (spam_total_words + vocab_size))
            p_ham = model_weights["ham_word_probs"].get(token, 1 / (ham_total_words + vocab_size))
            
            log_spam += math.log(p_spam)
            log_ham += math.log(p_ham)
            
            matched_tokens.append({
                "word": token,
                "pSpam": p_spam,
                "pHam": p_ham,
                "ratio": p_spam / p_ham
            })
            
    # Calculate probability scores using softmax normalization
    max_log = max(log_spam, log_ham)
    exp_spam = math.exp(log_spam - max_log)
    exp_ham = math.exp(log_ham - max_log)
    
    prob_spam = exp_spam / (exp_spam + exp_ham)
    prob_ham = exp_ham / (exp_spam + exp_ham)
    
    is_spam = prob_spam > prob_ham
    confidence = prob_spam if is_spam else prob_ham
    
    return {
        "isSpam": is_spam,
        "confidence": confidence,
        "logSpam": log_spam,
        "logHam": log_ham,
        "tokens": tokens,
        "matched": matched_tokens
    }

# 3. Safe Browsing / Heuristics Link Threat Scanner
def scan_url(url):
    print(f"Scanning URL: {url}")
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    
    # A. If API key exists, run Google Safe Browsing Check
    if GOOGLE_API_KEY:
        print("Running Google Safe Browsing API check...")
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
            req_body = {
                "client": {"clientId": "spamguard-core", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            req = urllib.request.Request(
                api_url,
                data=json.dumps(req_body).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                response = json.loads(res.read().decode("utf-8"))
                
            if "matches" in response:
                threats = [m["threatType"] for m in response["matches"]]
                return {
                    "status": "DANGER",
                    "source": "Google Safe Browsing API",
                    "details": f"Flagged by Google: {', '.join(threats)}",
                    "metrics": {
                        "malware": "MALWARE" in threats,
                        "phishing": "SOCIAL_ENGINEERING" in threats,
                        "unwanted": "UNWANTED_SOFTWARE" in threats
                    }
                }
            else:
                return {
                    "status": "SAFE",
                    "source": "Google Safe Browsing API",
                    "details": "Verified as safe by Google's threat database.",
                    "metrics": {"malware": False, "phishing": False, "unwanted": False}
                }
        except Exception as e:
            print(f"Google Safe Browsing API call failed: {e}. Falling back to Heuristics.")
            # Fall back to local check if API call fails
            
    # B. Heuristic Scanner (Run when no API key exists, or API call fails)
    print("Running local heuristic URL reputation checks...")
    flags = []
    
    # 1. Suspicious brand name impersonations
    brand_keywords = ["paypal", "netflix", "walmart", "amazon", "chase", "bank", "secure", "login", "update", "verify", "signin", "account", "support", "billing", "giftcard", "free-cash"]
    for kw in brand_keywords:
        # Check if brand keyword is in subdomain but not primary domain (impersonation check)
        parts = domain.split('.')
        primary_domain = parts[-2] if len(parts) > 1 else domain
        if len(parts) > 2:
            subdomains = parts[:-2]
            if kw in "".join(subdomains) and kw != primary_domain:
                flags.append(f"Brand Impersonation Threat (keyword '{kw}' in subdomain)")
        
        # Check if brand keyword is in the main domain, but the domain isn't exactly just the brand
        if kw in primary_domain and primary_domain != kw:
            flags.append(f"Suspicious Brand Inclusion (keyword '{kw}' mixed in domain)")
        
    # 2. Suspicious TLD check
    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club", ".work", ".click", ".link", ".info", ".buzz", ".fit", ".bid", ".live", ".cc", ".stream", ".download"]
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            flags.append(f"Suspicious Top-Level Domain ({tld})")
            break
            
    # 3. Numeric domain (IP addresses used as hosts)
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(ip_pattern, domain):
        flags.append("IP Address Host (commonly bypasses DNS registration filters)")
        
    # 4. Known URL shorteners (often mask phishing targets)
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "rebrand.ly", "goo.gl", "ow.ly", "short.io"]
    if domain in shorteners:
        flags.append("Obfuscated Link (uses a public URL shortener to hide final target)")
        
    # 5. Excessive subdomains or parameters
    if domain.count('.') >= 4:
        flags.append("Excessive Subdomains (indicates phishing redirection hierarchy)")
    if len(parsed.query) > 100 or parsed.query.count('=') > 4:
        flags.append("Suspicious Query Parameters (potential tracking or token harvesting)")
        
    # 6. Free Hosting Platforms (commonly abused for temporary phishing pages)
    free_hosts = ["wixsite.com", "weebly.com", "000webhostapp.com", "blogspot.com", "wordpress.com", "glitch.me", "herokuapp.com", "repl.co"]
    for host in free_hosts:
        if domain.endswith(host):
            flags.append(f"Free Hosting Provider ({host}) - High risk of temporary phishing page")
            break
            
    # 7. Unencrypted HTTP requesting sensitive data
    if parsed.scheme == "http":
        sensitive_paths = ["login", "signin", "bank", "secure", "verify", "account", "auth"]
        if any(s in parsed.path.lower() or s in parsed.query.lower() for s in sensitive_paths):
            flags.append("Unencrypted Connection (HTTP) requesting sensitive login/verification data")
            
    # 8. Basic Typo-Squatting (Character substitution on major brands)
    # Checks for m->rn, l->1, o->0, etc.
    major_brands = ["amazon", "paypal", "netflix", "microsoft", "google", "apple", "facebook", "chase"]
    domain_no_tld = domain.split('.')[0]
    for brand in major_brands:
        # Avoid flagging the actual brand
        if brand in domain:
            continue
        # Check for simple homoglyph substitutions
        suspicious_variant = domain_no_tld.replace("rn", "m").replace("1", "l").replace("0", "o")
        if brand in suspicious_variant and brand not in domain_no_tld:
            flags.append(f"Typo-Squatting Detected (attempting to mimic {brand})")

    if flags:
        return {
            "status": "SUSPICIOUS",
            "source": "Local Heuristics Engine",
            "details": "Flagged by local security heuristic rule checks.",
            "flags": flags,
            "metrics": {
                "malware": "IP Address Host" in "".join(flags),
                "phishing": any(x in f for f in flags for x in ["Impersonation", "Redirection", "Shortener", "Typo", "Free Hosting", "Unencrypted"]),
                "unwanted": "Suspicious Top-Level Domain" in "".join(flags)
            }
        }
    
    return {
        "status": "SAFE",
        "source": "Local Heuristics Engine",
        "details": "Passed all local heuristic threat anomaly checks.",
        "metrics": {"malware": False, "phishing": False, "unwanted": False}
    }

# 4. News / Fact Checker (Google Fact Check Proxy + Wikipedia Fallback)
# Local static fact checker matching database of common fake claims
LOCAL_FACT_DATABASE = [
    {
        "query": "flat earth",
        "claim": "The Earth is flat and NASA fakes all satellite images.",
        "claimant": "Flat Earth Society",
        "rating": "FALSE",
        "publisher": "PolitiFact",
        "details": "Multiple scientific proofs, satellite imagery, and space travels verify the earth is an oblate spheroid."
    },
    {
        "query": "vaccine microchip",
        "claim": "COVID-19 vaccines contain 5G microchips to track populations.",
        "claimant": "Social Media Posts",
        "rating": "FALSE",
        "publisher": "Snopes",
        "details": "Ingredients lists of approved vaccines show no electronic components. Microchips cannot fit through vaccine needles."
    },
    {
        "query": "moon landing",
        "claim": "The Apollo 11 moon landing was faked on a Hollywood stage.",
        "claimant": "Conspiracy Theorists",
        "rating": "FALSE",
        "publisher": "Snopes",
        "details": "Over 800 lbs of moon rocks, independent tracking from multiple nations, and lunar lasers confirm astronauts landed on the moon."
    },
    {
        "query": "5g virus",
        "claim": "5G cell towers transmit and cause COVID-19.",
        "claimant": "Internet rumors",
        "rating": "FALSE",
        "publisher": "World Health Organization",
        "details": "Viruses cannot travel on radio waves or mobile networks. COVID-19 spread rapidly in countries without any 5G infrastructure."
    },
    {
        "query": "amitabh bachan died",
        "claim": "Bollywood actor Amitabh Bachchan has died.",
        "claimant": "Social Media Rumors",
        "rating": "FALSE",
        "publisher": "News Verification Outlets",
        "details": "This is a recurring celebrity death hoax. Amitabh Bachchan is alive. Always verify celebrity deaths via official statements or credible news networks."
    },
    {
        "query": "amitabh bachchan died",
        "claim": "Bollywood actor Amitabh Bachchan has passed away.",
        "claimant": "Social Media WhatsApp Forwards",
        "rating": "FALSE",
        "publisher": "Fact Checkers",
        "details": "Recurring death hoax. The actor is alive and well."
    }
]

def fact_check_news(query):
    print(f"Fact checking query: {query}")
    # A. If API key exists, run Google Fact Check Tools API check
    if GOOGLE_API_KEY:
        print("Running Google Fact Check API check...")
        try:
            encoded = urllib.parse.quote(query)
            api_url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={encoded}&key={GOOGLE_API_KEY}"
            req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as res:
                response = json.loads(res.read().decode("utf-8"))
            
            if "claims" in response:
                formatted_claims = []
                for claim in response["claims"][:6]: # limit to 6 claims
                    rating = "UNKNOWN"
                    publisher = "Unknown Publisher"
                    url = "#"
                    
                    if "claimReview" in claim and len(claim["claimReview"]) > 0:
                        review = claim["claimReview"][0]
                        rating = review.get("textualRating", "No Rating").upper()
                        publisher = review.get("publisher", {}).get("name", "Fact Checker")
                        url = review.get("url", "#")
                        
                    formatted_claims.append({
                        "text": claim.get("text", ""),
                        "claimant": claim.get("claimant", "Unknown Source"),
                        "rating": rating,
                        "publisher": publisher,
                        "url": url,
                        "details": f"Fact checked by {publisher}."
                    })
                return {
                    "status": "RESULTS_FOUND",
                    "source": "Google Fact Check API",
                    "claims": formatted_claims
                }
        except Exception as e:
            print(f"Google Fact Check API failed: {e}. Falling back to Keyless verification.")

    # B. Keyless Fallback Engine (Scrapes Wikipedia API + Local Fact Database matches)
    print("Running keyless Fact Check fallbacks...")
    
    # 1. First, check local static database
    local_matches = []
    query_lower = query.lower()
    for item in LOCAL_FACT_DATABASE:
        if item["query"] in query_lower:
            local_matches.append({
                "text": item["claim"],
                "claimant": item["claimant"],
                "rating": item["rating"],
                "publisher": item["publisher"],
                "url": "https://www.snopes.com" if item["publisher"] == "Snopes" else "https://www.politifact.com",
                "details": item["details"]
            })
            
    # 1.5 Dynamic Wikipedia / Live Fact Checker (Keyless)
    # Automatically checks for celebrity status / death hoaxes dynamically
    death_keywords = ["died", "death", "dies", "passed away", "killed", "dead", "funeral", "rip"]
    is_death_claim = any(re.search(r'\b' + kw + r'\b', query_lower) for kw in death_keywords)
    
    if not local_matches and is_death_claim:
        try:
            # Extract target entity name by removing death-related verbs and adjectives
            entity_search = query
            for kw in death_keywords:
                entity_search = re.sub(r'\b' + kw + r'\b', '', entity_search, flags=re.IGNORECASE)
            entity_search = re.sub(r'\b(the|indian|legend|actor|singer|famous|celebrity|politician|cricketer|player|president|pm|minister)\b', '', entity_search, flags=re.IGNORECASE)
            entity_search = re.sub(r'\s+', ' ', entity_search).strip()
            
            if entity_search:
                print(f"Dynamic verification check for entity: '{entity_search}'")
                encoded_search = urllib.parse.quote(entity_search)
                search_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={encoded_search}&format=json&origin=*"
                req = urllib.request.Request(search_url, headers={"User-Agent": "SpamGuardCore/1.0"})
                with urllib.request.urlopen(req, timeout=5) as res:
                    search_res = json.loads(res.read().decode("utf-8"))
                    
                if "query" in search_res and "search" in search_res["query"] and search_res["query"]["search"]:
                    top_result = search_res["query"]["search"][0]
                    title = top_result["title"]
                    
                    # Fetch page summary to check living status
                    encoded_title = urllib.parse.quote(title)
                    extract_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exintro&explaintext&titles={encoded_title}&format=json&origin=*"
                    req = urllib.request.Request(extract_url, headers={"User-Agent": "SpamGuardCore/1.0"})
                    with urllib.request.urlopen(req, timeout=5) as res:
                        extract_res = json.loads(res.read().decode("utf-8"))
                        
                    pages = extract_res.get("query", {}).get("pages", {})
                    if pages:
                        page_id = list(pages.keys())[0]
                        if page_id != "-1":
                            extract = pages[page_id].get("extract", "")
                            
                            # Heuristics to check if person has died
                            has_death_indicator = False
                            
                            # Check birth-death parenthesis (e.g. "(born 24 April 1973)")
                            parenthesis_match = re.search(r'\(([^)]+)\)', extract[:300])
                            if parenthesis_match:
                                paren_content = parenthesis_match.group(1)
                                if any(x in paren_content for x in ["died", "death", "–", " - ", "—"]):
                                    parts = re.split(r'–|-|—', paren_content)
                                    if len(parts) > 1 and any(char.isdigit() for char in parts[1]):
                                        has_death_indicator = True
                                        
                            # Check first sentence verb tense (past tense "was" vs present tense "is")
                            first_sentence = extract.split(". ")[0].lower()
                            is_past = "was" in first_sentence and "is" not in first_sentence
                            if any(x in first_sentence for x in ["died", "passed away", "assassinated"]):
                                has_death_indicator = True
                            if is_past:
                                has_death_indicator = True
                                
                            wiki_url = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title)}"
                            if not has_death_indicator:
                                # Person is currently alive, so death claim is a hoax!
                                local_matches.append({
                                    "text": f"{title} has passed away",
                                    "claimant": "Social Media Rumors / WhatsApp",
                                    "rating": "FALSE / HOAX",
                                    "publisher": "Wikipedia Verification Engine",
                                    "url": wiki_url,
                                    "details": f"Wikipedia records confirm that {title} is currently ALIVE (born with no recorded death date). The claim that they have died is a hoax."
                                })
                            else:
                                # Person is deceased, so death claim is verified/true
                                local_matches.append({
                                    "text": f"{title} has passed away",
                                    "claimant": "News Reports",
                                    "rating": "VERIFIED / TRUE",
                                    "publisher": "Wikipedia Verification Engine",
                                    "url": wiki_url,
                                    "details": f"Wikipedia records confirm the death of {title}. Details: {extract[:200]}..."
                                })
        except Exception as dynamic_err:
            print(f"Dynamic Wikipedia verification failed: {dynamic_err}")

    # 1.6 Live Google Search Fallback Scraper (Keyless)
    # Automatically searches Google for the claim to see if front-page results identify it as a hoax
    if not local_matches:
        try:
            print("Scraping Google Search for real-time fact checks...")
            encoded_query = urllib.parse.quote(query)
            google_url = f"https://www.google.com/search?q=fact+check+{encoded_query}"
            google_req = urllib.request.Request(google_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
            html_content = urllib.request.urlopen(google_req, timeout=5).read().decode('utf-8').lower()
            
            # Avoid matching "false" from script blocks, make sure to look for specific debunking terms
            if any(x in html_content for x in ["fake news", "hoax", "debunked", "false claim", "rumor"]):
                local_matches.append({
                    "text": query.title(),
                    "claimant": "Internet / Social Media",
                    "rating": "FALSE",
                    "publisher": "Google Search Aggregate",
                    "url": google_url,
                    "details": "Aggregated Google Search results strongly indicate this query is a documented hoax, rumor, or fake news."
                })
        except Exception as e:
            print(f"Google Scrape failed: {e}")
            
    if local_matches:
        return {
            "status": "RESULTS_FOUND",
            "source": "Local Fact-Check Repository",
            "claims": local_matches
        }
        
    # 2. Query Wikipedia Search API (Completely free, no key required)
    try:
        print("Querying Wikipedia Open Search API...")
        wiki_query = urllib.parse.quote(query)
        wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={wiki_query}&format=json&origin=*"
        req = urllib.request.Request(wiki_url, headers={"User-Agent": "SpamGuardCore/1.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            wiki_res = json.loads(res.read().decode("utf-8"))
            
        if "query" in wiki_res and "search" in wiki_res["query"]:
            wiki_results = wiki_res["query"]["search"]
            claims = []
            for item in wiki_results[:4]: # limit to 4 results
                snippet_clean = re.sub(r'<span class="searchmatch">|</span>', '', item["snippet"])
                snippet_clean = re.sub(r'&quot;|\xa0', ' ', snippet_clean)
                
                # Deduce dynamic credibility based on vocabulary triggers in snippet
                snippet_lower = snippet_clean.lower()
                rating = "NEUTRAL"
                details = "Wikipedia reference article content matches this query."
                
                if any(x in snippet_lower for x in ["hoax", "conspiracy theory", "debunked", "false", "disproven", "pseudoscience"]):
                    rating = "FALSE / DEBUNKED"
                    details = "Wikipedia identifies this query topic as a documented hoax, conspiracy theory, or pseudoscience."
                elif any(x in snippet_lower for x in ["proven", "confirmed", "scientific law", "consensus"]):
                    rating = "VERIFIED / TRUE"
                    details = "Wikipedia article text aligns with consensus/verified information."
                    
                claims.append({
                    "text": item["title"],
                    "claimant": "Wikipedia Encyclopedia",
                    "rating": rating,
                    "publisher": "Wikipedia Foundation",
                    "url": f"https://en.wikipedia.org/wiki/{urllib.parse.quote(item['title'])}",
                    "details": snippet_clean + "..." if len(snippet_clean) > 0 else details
                })
            
            if claims:
                return {
                    "status": "RESULTS_FOUND",
                    "source": "Wikipedia Open Verification Engine",
                    "claims": claims
                }
    except Exception as wiki_err:
        print(f"Wikipedia Open Search query failed: {wiki_err}")
        
    return {
        "status": "NO_RESULTS",
        "source": "Keyless Search Engines",
        "claims": [],
        "details": "No verified claims or encyclopedic references matched your exact query terms."
    }

# HTTP Handler routing requests
class SpamGuardRequestHandler(http.server.SimpleHTTPRequestHandler):
    
    # Overwrite log_message to prevent console clutter during testing
    def log_message(self, format, *args):
        # We can still print request methods for local visibility
        print(f"LOG: {self.client_address[0]} - {args[0]} {args[1]}")
        
    def do_OPTIONS(self):
        # Handle CORS preflight options request
        self.send_response(200, "ok")
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type")
        self.end_headers()
        
    def _get_session_user(self):
        cookie_header = self.headers.get('Cookie')
        if not cookie_header:
            return None
        cookie = cookies.SimpleCookie(cookie_header)
        session_cookie = cookie.get('session_id')
        if not session_cookie:
            return None
            
        session_id = session_cookie.value
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT users.username FROM sessions JOIN users ON sessions.user_id = users.id WHERE session_id = ?", (session_id,))
            user = c.fetchone()
            conn.close()
            return user[0] if user else None
        except Exception:
            return None

    def do_POST(self):
        # We handle sending headers per route now to support cookies
        # Read content length
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b"{}"
        
        try:
            req_data = json.loads(post_data.decode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"Invalid JSON payload: {e}"}).encode('utf-8'))
            return
            
        # Auth Routes
        if self.path == '/api/signup':
            username = req_data.get("username", "").strip()
            password = req_data.get("password", "").strip()
            if not username or not password:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Username and password required"}).encode('utf-8'))
                return
                
            pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))
                conn.commit()
                conn.close()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode('utf-8'))
            except sqlite3.IntegrityError:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Username already exists"}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        elif self.path == '/api/login':
            username = req_data.get("username", "").strip()
            password = req_data.get("password", "").strip()
            pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", (username, pw_hash))
                user = c.fetchone()
                
                if user:
                    session_id = secrets.token_hex(16)
                    c.execute("INSERT INTO sessions (session_id, user_id) VALUES (?, ?)", (session_id, user[0]))
                    conn.commit()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    cookie = cookies.SimpleCookie()
                    cookie['session_id'] = session_id
                    cookie['session_id']['path'] = '/'
                    cookie['session_id']['httponly'] = True
                    self.send_header('Set-Cookie', cookie.output(header='', sep='').strip())
                    self.end_headers()
                    self.wfile.write(json.dumps({"success": True}).encode('utf-8'))
                else:
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Invalid credentials"}).encode('utf-8'))
                conn.close()
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return
            
        elif self.path == '/api/logout':
            cookie_header = self.headers.get('Cookie')
            if cookie_header:
                cookie = cookies.SimpleCookie(cookie_header)
                if 'session_id' in cookie:
                    session_id = cookie['session_id'].value
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                    conn.commit()
                    conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            # Clear cookie
            cookie = cookies.SimpleCookie()
            cookie['session_id'] = ''
            cookie['session_id']['path'] = '/'
            cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
            self.send_header('Set-Cookie', cookie.output(header='', sep='').strip())
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode('utf-8'))
            return
            
        # Protect API routes
        if not self._get_session_user():
            self.send_response(401)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized. Please login."}).encode('utf-8'))
            return
            
        # Default API response headers
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Route 1: Message classification
        if self.path == '/api/analyze-text':
            text = req_data.get("text", "").strip()
            if not text:
                self.wfile.write(json.dumps({"error": "Empty input text"}).encode('utf-8'))
                return
            result = classify_text(text)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        # Route 2: URL link threat scanner
        elif self.path == '/api/scan-link':
            url = req_data.get("url", "").strip()
            if not url:
                self.wfile.write(json.dumps({"error": "Empty URL link string"}).encode('utf-8'))
                return
            result = scan_url(url)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        # Route 3: News fact checker
        elif self.path == '/api/fact-check':
            query = req_data.get("query", "").strip()
            if not query:
                self.wfile.write(json.dumps({"error": "Empty search query"}).encode('utf-8'))
                return
            result = fact_check_news(query)
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        else:
            self.send_response(404)
            self.end_headers()
            
    # GET method to serve static files plus state configs
    def do_GET(self):
        # Redirect root to login.html or dashboard based on session
        if self.path == '/':
            if self._get_session_user():
                self.send_response(302)
                self.send_header('Location', '/dashboard.html')
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header('Location', '/login.html')
                self.end_headers()
            return
            
        # Protect dashboard.html
        if self.path.startswith('/dashboard.html'):
            if not self._get_session_user():
                self.send_response(302)
                self.send_header('Location', '/login.html')
                self.end_headers()
                return
                
        # Redirect authenticated users away from login/signup pages
        if self.path in ['/login.html', '/signup.html']:
            if self._get_session_user():
                self.send_response(302)
                self.send_header('Location', '/dashboard.html')
                self.end_headers()
                return

        # Custom route to retrieve system statuses
        if self.path == '/api/system-status':
            if not self._get_session_user():
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode('utf-8'))
                return
                
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            status = {
                "api_attached": bool(GOOGLE_API_KEY),
                "model_trained": model_weights is not None,
                "vocab_size": model_weights.get("vocab_size", 0) if model_weights else 0,
                "spam_words": model_weights.get("spam_total_words", 0) if model_weights else 0,
                "ham_words": model_weights.get("ham_total_words", 0) if model_weights else 0
            }
            self.wfile.write(json.dumps(status).encode('utf-8'))
            return
            
        # Fall back to default handler for static files
        super().do_GET()

def run_server():
    # Force reuse address to avoid Port Occupied error when restarting quickly
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), SpamGuardRequestHandler) as httpd:
        print(f"SpamGuard Core Web Server running at http://localhost:{PORT}")
        print(f"Google API Key Attached: {bool(GOOGLE_API_KEY)} (Value length: {len(GOOGLE_API_KEY)})")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
            httpd.shutdown()

if __name__ == "__main__":
    run_server()
