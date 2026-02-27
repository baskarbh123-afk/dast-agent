class Wordlists:
    COMMON_PARAMS = [
        "id", "page", "search", "q", "query", "name", "email", "user",
        "username", "password", "pass", "token", "key", "api_key", "apikey",
        "secret", "file", "path", "url", "uri", "redirect", "callback",
        "return", "next", "dest", "source", "ref", "type", "action",
        "cmd", "command", "exec", "debug", "test", "mode", "format",
        "output", "input", "data", "value", "content", "text", "body",
        "message", "comment", "title", "description", "category", "tag",
        "sort", "order", "limit", "offset", "skip", "count", "size",
        "width", "height", "color", "lang", "language", "locale",
        "template", "theme", "view", "layout", "style", "class",
        "method", "function", "handler", "filter", "include", "require",
        "module", "plugin", "extension", "version", "v", "admin",
        "role", "group", "permission", "access", "level", "status",
        "state", "active", "enabled", "disabled", "hidden", "private",
        "public", "internal", "external", "config", "setting", "option",
        "param", "arg", "var", "field", "column", "table", "db",
        "database", "schema", "collection", "bucket", "region",
        "endpoint", "host", "port", "protocol", "domain", "subdomain",
        "ip", "address", "network", "proxy", "gateway",
    ]

    COMMON_DIRS = [
        "admin", "api", "app", "assets", "auth", "backup", "bin",
        "cgi-bin", "config", "console", "dashboard", "data", "db",
        "debug", "dev", "docs", "download", "env", "error", "files",
        "graphql", "health", "help", "hidden", "images", "img",
        "include", "info", "internal", "js", "json", "lib", "log",
        "login", "logs", "media", "metrics", "monitoring", "old",
        "panel", "portal", "private", "public", "rest", "scripts",
        "secret", "server-status", "settings", "setup", "sql",
        "static", "status", "storage", "swagger", "system", "temp",
        "test", "tmp", "tools", "upload", "uploads", "user", "users",
        "v1", "v2", "v3", "vendor", "web", "webhook", "wp-admin",
        "wp-content", "wp-includes", "xml", "xmlrpc",
    ]

    COMMON_FILES = [
        ".env", ".git/config", ".htaccess", ".htpasswd",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "web.config", "server-info", "server-status",
        "phpinfo.php", "info.php", "test.php",
        "wp-config.php.bak", "config.php.bak",
        "database.yml", "application.yml",
        ".DS_Store", "Thumbs.db",
        "package.json", "composer.json",
        ".gitignore", "Dockerfile",
        "swagger.json", "openapi.json", "openapi.yaml",
        "graphql", "graphiql",
        "actuator/health", "actuator/env",
        "_debug_toolbar/", "debug/default/view",
        "trace.axd", "elmah.axd",
        "api-docs", "api/docs", "api/swagger",
    ]

    API_PATHS = [
        "/api/v1/users", "/api/v1/admin", "/api/v1/config",
        "/api/v2/users", "/api/v2/admin",
        "/api/users", "/api/admin", "/api/config",
        "/api/health", "/api/status", "/api/info",
        "/api/debug", "/api/test", "/api/internal",
        "/api/graphql", "/graphql", "/graphiql",
        "/api/swagger.json", "/api/openapi.json",
        "/rest/api/latest", "/rest/api/2",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",
    ]

    @classmethod
    def get(cls, name: str) -> list[str]:
        mapping = {
            "params": cls.COMMON_PARAMS,
            "dirs": cls.COMMON_DIRS,
            "files": cls.COMMON_FILES,
            "api_paths": cls.API_PATHS,
        }
        return mapping.get(name, cls.COMMON_PARAMS)
