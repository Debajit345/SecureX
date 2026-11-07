from difflib import SequenceMatcher
from urllib.parse import urlsplit

SUSPICIOUS_TERMS = {"login", "verify", "secure", "account", "update", "payment", "signin", "password", "wallet"}
KNOWN_BRANDS = ("google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram", "netflix", "linkedin")


def analyze_url(url: str) -> list[dict]:
    p = urlsplit(url)
    host = p.hostname or ""
    findings = []
    if p.scheme != "https":
        findings.append({"severity": "medium", "title": "Connection does not use HTTPS", "detail": "The URL uses HTTP, so traffic is not protected by TLS."})
    if len(host.split(".")) >= 5:
        findings.append({"severity": "low", "title": "Unusually deep subdomain", "detail": "The hostname has several subdomain levels, which can make the registered domain harder to spot."})
    if "xn--" in host:
        findings.append({"severity": "medium", "title": "Internationalized hostname", "detail": "The hostname uses punycode; visually similar characters may be present."})
    registrable_guess = host.split(".")[-2] if len(host.split(".")) > 1 else host
    normalized_label = registrable_guess.lower().replace("-", "")
    for brand in KNOWN_BRANDS:
        similarity = SequenceMatcher(None, normalized_label, brand).ratio()
        if normalized_label != brand and similarity >= 0.78:
            findings.append({"severity": "medium", "title": "Possible brand lookalike", "detail": f"The registered-domain label resembles {brand.title()}. This heuristic can produce false positives."})
            break
    if host.count("-") >= 3:
        findings.append({"severity": "low", "title": "Many hyphens in hostname", "detail": "Multiple hyphens can appear in deceptive lookalike domains."})
    terms = sorted(t for t in SUSPICIOUS_TERMS if t in (host + p.path).lower())
    if terms:
        findings.append({"severity": "low", "title": "Sensitive-action wording in URL", "detail": "URL contains: " + ", ".join(terms) + ". This is only a weak signal."})
    return findings
