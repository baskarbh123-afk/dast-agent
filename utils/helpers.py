from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin
import hashlib
import re


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    netloc = parsed.netloc.lower().rstrip(".")
    path = parsed.path.rstrip("/") or "/"
    # Sort query parameters for consistent dedup
    params = parse_qs(parsed.query, keep_blank_values=True)
    sorted_query = urlencode(sorted(params.items()), doseq=True)
    return urlunparse((scheme, netloc, path, "", sorted_query, ""))


def extract_params(url: str) -> dict[str, list[str]]:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def is_same_origin(url1: str, url2: str) -> bool:
    p1, p2 = urlparse(url1), urlparse(url2)
    return (p1.scheme, p1.netloc.lower()) == (p2.scheme, p2.netloc.lower())


def url_fingerprint(url: str, method: str = "GET") -> str:
    parsed = urlparse(url)
    param_names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
    key = f"{method}|{parsed.netloc}{parsed.path}|{'&'.join(param_names)}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def strip_url_params(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def build_url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = urlencode(params)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))


def resolve_url(base: str, relative: str) -> str:
    return urljoin(base, relative)


def extract_forms(html: str, base_url: str) -> list[dict]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        full_action = resolve_url(base_url, action) if action else base_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_name = inp.get("name")
            if not input_name:
                continue
            input_type = inp.get("type", "text")
            input_value = inp.get("value", "")
            inputs.append({"name": input_name, "type": input_type, "value": input_value})

        forms.append({"action": full_action, "method": method, "inputs": inputs})
    return forms


def extract_links(html: str, base_url: str) -> set[str]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    links = set()
    for tag in soup.find_all(["a", "link", "area"]):
        href = tag.get("href")
        if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            links.add(resolve_url(base_url, href))
    for tag in soup.find_all(["script", "img", "iframe", "source", "embed"]):
        src = tag.get("src")
        if src and not src.startswith("data:"):
            links.add(resolve_url(base_url, src))
    return links


def extract_js_endpoints(js_content: str) -> set[str]:
    patterns = [
        r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[^"\']*)?)["\']',
        r'["\'](?:https?://[^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'endpoint[s]?\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:api|url|uri|path|route)\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    endpoints = set()
    for pattern in patterns:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            endpoint = match.group(1) if match.lastindex else match.group(0)
            endpoint = endpoint.strip("\"'")
            if len(endpoint) > 2 and not endpoint.endswith((".js", ".css", ".png", ".jpg", ".gif")):
                endpoints.add(endpoint)
    return endpoints


def generate_boundary_values(param_type: str = "string") -> list[str]:
    if param_type == "integer":
        return ["0", "-1", "1", "9999999", "-9999999", "2147483647", "-2147483648"]
    return [
        "",
        " ",
        "null",
        "undefined",
        "true",
        "false",
        "[]",
        "{}",
        "../",
        "..\\",
        "%00",
        "%0a",
        "\r\n",
        "A" * 1000,
    ]
