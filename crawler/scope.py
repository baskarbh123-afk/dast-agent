import re
from urllib.parse import urlparse
import tldextract


class ScopeManager:
    def __init__(
        self,
        target_url: str,
        include_subdomains: bool = True,
        allowed_domains: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        excluded_extensions: list[str] | None = None,
    ):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_scheme = parsed.scheme
        self.target_netloc = parsed.netloc.lower()

        ext = tldextract.extract(target_url)
        self.target_domain = f"{ext.domain}.{ext.suffix}"
        self.target_subdomain = ext.subdomain
        self.include_subdomains = include_subdomains

        self.allowed_domains = set(d.lower() for d in (allowed_domains or []))
        self.allowed_domains.add(self.target_netloc)

        self.excluded_paths = excluded_paths or []
        self.excluded_extensions = excluded_extensions or [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".eot",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv",
            ".pdf", ".zip", ".tar", ".gz", ".rar",
        ]

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.netloc.lower().split(":")[0]

        if not self._domain_allowed(hostname):
            return False

        path = parsed.path.lower()
        for ext in self.excluded_extensions:
            if path.endswith(ext):
                return False

        for excluded in self.excluded_paths:
            if path.startswith(excluded.lower()):
                return False

        return True

    def _domain_allowed(self, hostname: str) -> bool:
        if hostname == self.target_netloc.split(":")[0]:
            return True

        if self.include_subdomains:
            ext = tldextract.extract(hostname)
            check_domain = f"{ext.domain}.{ext.suffix}"
            if check_domain == self.target_domain:
                return True

        for allowed in self.allowed_domains:
            allowed_host = allowed.split(":")[0]
            if hostname == allowed_host:
                return True
            if self.include_subdomains and hostname.endswith(f".{allowed_host}"):
                return True

        return False

    def get_scope_summary(self) -> dict:
        return {
            "target": self.target_url,
            "domain": self.target_domain,
            "include_subdomains": self.include_subdomains,
            "allowed_domains": list(self.allowed_domains),
            "excluded_paths": self.excluded_paths,
        }
