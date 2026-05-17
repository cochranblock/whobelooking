// Unlicense — public domain — whobelooking.org
//! Canonical surface-area probe list.
//!
//! Single source of truth: `scan_api.rs` imports `PROBES` directly from this
//! crate; the browser `/scan` page calls `getProbes()` via the WASM export
//! (`f406`) and gets the same slice serialized as a JS array.
//!
//! Edit here — nowhere else.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Probe {
    pub path: &'static str,
    pub label: &'static str,
    pub sev: &'static str,
}

pub const PROBES: &[Probe] = &[
    // ── CRITICAL — secrets, keys, raw data ───────────────────────────────
    Probe {
        path: "/.env",
        label: ".env",
        sev: "critical",
    },
    Probe {
        path: "/.env.local",
        label: ".env.local",
        sev: "critical",
    },
    Probe {
        path: "/.env.production",
        label: ".env.production",
        sev: "critical",
    },
    Probe {
        path: "/.env.development",
        label: ".env.development",
        sev: "critical",
    },
    Probe {
        path: "/.env.staging",
        label: ".env.staging",
        sev: "critical",
    },
    Probe {
        path: "/.env.backup",
        label: ".env.backup",
        sev: "critical",
    },
    Probe {
        path: "/.env.bak",
        label: ".env.bak",
        sev: "critical",
    },
    Probe {
        path: "/web.config",
        label: "web.config",
        sev: "critical",
    },
    Probe {
        path: "/config.php",
        label: "PHP config",
        sev: "critical",
    },
    Probe {
        path: "/config.php.bak",
        label: "PHP config backup",
        sev: "critical",
    },
    Probe {
        path: "/wp-config.php",
        label: "WordPress config",
        sev: "critical",
    },
    Probe {
        path: "/wp-config.php.bak",
        label: "WordPress config backup",
        sev: "critical",
    },
    Probe {
        path: "/configuration.php",
        label: "Joomla config",
        sev: "critical",
    },
    Probe {
        path: "/config.yml",
        label: "config.yml",
        sev: "critical",
    },
    Probe {
        path: "/config.yaml",
        label: "config.yaml",
        sev: "critical",
    },
    Probe {
        path: "/config.json",
        label: "config.json",
        sev: "critical",
    },
    Probe {
        path: "/settings.py",
        label: "Django settings",
        sev: "critical",
    },
    Probe {
        path: "/local_settings.py",
        label: "Django local settings",
        sev: "critical",
    },
    Probe {
        path: "/database.yml",
        label: "Rails database.yml",
        sev: "critical",
    },
    Probe {
        path: "/config/database.yml",
        label: "Rails config/database.yml",
        sev: "critical",
    },
    Probe {
        path: "/application.yml",
        label: "Spring application.yml",
        sev: "critical",
    },
    Probe {
        path: "/application.properties",
        label: "Spring application.properties",
        sev: "critical",
    },
    Probe {
        path: "/credentials.json",
        label: "credentials.json",
        sev: "critical",
    },
    Probe {
        path: "/secrets.json",
        label: "secrets.json",
        sev: "critical",
    },
    Probe {
        path: "/secrets.yml",
        label: "secrets.yml",
        sev: "critical",
    },
    Probe {
        path: "/secrets.yaml",
        label: "secrets.yaml",
        sev: "critical",
    },
    Probe {
        path: "/.git/HEAD",
        label: "Git HEAD",
        sev: "critical",
    },
    Probe {
        path: "/.git/config",
        label: "Git config",
        sev: "critical",
    },
    Probe {
        path: "/.git/COMMIT_EDITMSG",
        label: "Git last commit msg",
        sev: "critical",
    },
    Probe {
        path: "/.gitconfig",
        label: ".gitconfig",
        sev: "critical",
    },
    Probe {
        path: "/backup.sql",
        label: "SQL backup",
        sev: "critical",
    },
    Probe {
        path: "/db.sql",
        label: "db.sql",
        sev: "critical",
    },
    Probe {
        path: "/database.sql",
        label: "database.sql",
        sev: "critical",
    },
    Probe {
        path: "/dump.sql",
        label: "dump.sql",
        sev: "critical",
    },
    Probe {
        path: "/backup.tar.gz",
        label: "Tarball backup",
        sev: "critical",
    },
    Probe {
        path: "/backup.zip",
        label: "Zip backup",
        sev: "critical",
    },
    Probe {
        path: "/site.tar.gz",
        label: "Site archive",
        sev: "critical",
    },
    Probe {
        path: "/www.tar.gz",
        label: "www archive",
        sev: "critical",
    },
    Probe {
        path: "/database.sqlite",
        label: "SQLite database",
        sev: "critical",
    },
    Probe {
        path: "/db.sqlite3",
        label: "SQLite3 database",
        sev: "critical",
    },
    Probe {
        path: "/id_rsa",
        label: "SSH private key",
        sev: "critical",
    },
    Probe {
        path: "/.ssh/id_rsa",
        label: ".ssh/id_rsa",
        sev: "critical",
    },
    Probe {
        path: "/private.key",
        label: "private.key",
        sev: "critical",
    },
    Probe {
        path: "/server.key",
        label: "server.key",
        sev: "critical",
    },
    Probe {
        path: "/.npmrc",
        label: ".npmrc (registry tokens)",
        sev: "critical",
    },
    Probe {
        path: "/.htpasswd",
        label: ".htpasswd",
        sev: "critical",
    },
    Probe {
        path: "/storage/logs/laravel.log",
        label: "Laravel log",
        sev: "critical",
    },
    Probe {
        path: "/laravel.log",
        label: "Laravel log (root)",
        sev: "critical",
    },
    Probe {
        path: "/wp-content/debug.log",
        label: "WordPress debug log",
        sev: "critical",
    },
    // ── HIGH — admin surfaces, info leaks, framework internals ───────────
    Probe {
        path: "/phpmyadmin/",
        label: "phpMyAdmin",
        sev: "high",
    },
    Probe {
        path: "/pma/",
        label: "phpMyAdmin (pma)",
        sev: "high",
    },
    Probe {
        path: "/info.php",
        label: "phpinfo",
        sev: "high",
    },
    Probe {
        path: "/phpinfo.php",
        label: "phpinfo (alt)",
        sev: "high",
    },
    Probe {
        path: "/test.php",
        label: "test.php",
        sev: "high",
    },
    Probe {
        path: "/actuator",
        label: "Spring actuator",
        sev: "high",
    },
    Probe {
        path: "/actuator/env",
        label: "Spring env dump",
        sev: "high",
    },
    Probe {
        path: "/actuator/beans",
        label: "Spring beans",
        sev: "high",
    },
    Probe {
        path: "/actuator/mappings",
        label: "Spring route map",
        sev: "high",
    },
    Probe {
        path: "/actuator/httptrace",
        label: "Spring HTTP trace",
        sev: "high",
    },
    Probe {
        path: "/actuator/loggers",
        label: "Spring loggers",
        sev: "high",
    },
    Probe {
        path: "/actuator/configprops",
        label: "Spring config props",
        sev: "high",
    },
    Probe {
        path: "/api/users",
        label: "API /users",
        sev: "high",
    },
    Probe {
        path: "/api/v1/users",
        label: "API v1 /users",
        sev: "high",
    },
    Probe {
        path: "/api/admin",
        label: "API /admin",
        sev: "high",
    },
    Probe {
        path: "/api/v1/admin",
        label: "API v1 /admin",
        sev: "high",
    },
    Probe {
        path: "/api/config",
        label: "API /config",
        sev: "high",
    },
    Probe {
        path: "/api/v1/config",
        label: "API v1 /config",
        sev: "high",
    },
    Probe {
        path: "/.svn/entries",
        label: "SVN entries",
        sev: "high",
    },
    Probe {
        path: "/.svn/wc.db",
        label: "SVN database",
        sev: "high",
    },
    Probe {
        path: "/package.json",
        label: "package.json",
        sev: "high",
    },
    Probe {
        path: "/composer.json",
        label: "composer.json",
        sev: "high",
    },
    Probe {
        path: "/_profiler/",
        label: "Symfony profiler",
        sev: "high",
    },
    Probe {
        path: "/elmah.axd",
        label: "ELMAH error log (ASP.NET)",
        sev: "high",
    },
    Probe {
        path: "/trace.axd",
        label: "ASP.NET trace",
        sev: "high",
    },
    Probe {
        path: "/wp-json/wp/v2/users",
        label: "WordPress user enum",
        sev: "high",
    },
    Probe {
        path: "/rails/info/routes",
        label: "Rails routes",
        sev: "high",
    },
    Probe {
        path: "/rails/info/properties",
        label: "Rails properties",
        sev: "high",
    },
    Probe {
        path: "/debug/pprof",
        label: "Go pprof",
        sev: "high",
    },
    Probe {
        path: "/debug/",
        label: "Debug panel",
        sev: "high",
    },
    // ── MEDIUM — CI/CD, dev files, admin panels ───────────────────────────
    Probe {
        path: "/admin/",
        label: "Admin panel",
        sev: "medium",
    },
    Probe {
        path: "/administrator/",
        label: "Joomla admin",
        sev: "medium",
    },
    Probe {
        path: "/wp-admin/",
        label: "WordPress admin",
        sev: "medium",
    },
    Probe {
        path: "/server-status",
        label: "Apache status",
        sev: "medium",
    },
    Probe {
        path: "/server-info",
        label: "Apache info",
        sev: "medium",
    },
    Probe {
        path: "/graphql",
        label: "GraphQL",
        sev: "medium",
    },
    Probe {
        path: "/swagger.json",
        label: "Swagger docs",
        sev: "medium",
    },
    Probe {
        path: "/openapi.json",
        label: "OpenAPI docs",
        sev: "medium",
    },
    Probe {
        path: "/api-docs",
        label: "API docs",
        sev: "medium",
    },
    Probe {
        path: "/api/docs",
        label: "API docs (alt)",
        sev: "medium",
    },
    Probe {
        path: "/xmlrpc.php",
        label: "XML-RPC",
        sev: "medium",
    },
    Probe {
        path: "/.DS_Store",
        label: ".DS_Store",
        sev: "medium",
    },
    Probe {
        path: "/.htaccess",
        label: ".htaccess",
        sev: "medium",
    },
    Probe {
        path: "/docker-compose.yml",
        label: "Docker Compose",
        sev: "medium",
    },
    Probe {
        path: "/docker-compose.yaml",
        label: "Docker Compose (yaml)",
        sev: "medium",
    },
    Probe {
        path: "/docker-compose.override.yml",
        label: "Docker Compose override",
        sev: "medium",
    },
    Probe {
        path: "/.travis.yml",
        label: "Travis CI config",
        sev: "medium",
    },
    Probe {
        path: "/Jenkinsfile",
        label: "Jenkinsfile",
        sev: "medium",
    },
    Probe {
        path: "/.circleci/config.yml",
        label: "CircleCI config",
        sev: "medium",
    },
    Probe {
        path: "/.gitlab-ci.yml",
        label: "GitLab CI config",
        sev: "medium",
    },
    Probe {
        path: "/bitbucket-pipelines.yml",
        label: "Bitbucket Pipelines",
        sev: "medium",
    },
    Probe {
        path: "/azure-pipelines.yml",
        label: "Azure Pipelines",
        sev: "medium",
    },
    Probe {
        path: "/install.php",
        label: "Install script",
        sev: "medium",
    },
    Probe {
        path: "/setup.php",
        label: "Setup script",
        sev: "medium",
    },
    Probe {
        path: "/install/",
        label: "Install dir",
        sev: "medium",
    },
    Probe {
        path: "/console",
        label: "Console",
        sev: "medium",
    },
    Probe {
        path: "/.gitignore",
        label: ".gitignore",
        sev: "medium",
    },
    Probe {
        path: "/.gitmodules",
        label: ".gitmodules",
        sev: "medium",
    },
    Probe {
        path: "/package-lock.json",
        label: "package-lock.json",
        sev: "medium",
    },
    Probe {
        path: "/yarn.lock",
        label: "yarn.lock",
        sev: "medium",
    },
    Probe {
        path: "/requirements.txt",
        label: "requirements.txt",
        sev: "medium",
    },
    Probe {
        path: "/Gemfile",
        label: "Gemfile",
        sev: "medium",
    },
    Probe {
        path: "/Makefile",
        label: "Makefile",
        sev: "medium",
    },
    Probe {
        path: "/cgi-bin/test-cgi",
        label: "CGI test",
        sev: "medium",
    },
    Probe {
        path: "/CHANGELOG.md",
        label: "CHANGELOG",
        sev: "medium",
    },
    Probe {
        path: "/CHANGELOG.txt",
        label: "CHANGELOG.txt",
        sev: "medium",
    },
    // ── LOW — version disclosure, old files ───────────────────────────────
    Probe {
        path: "/Dockerfile",
        label: "Dockerfile",
        sev: "low",
    },
    Probe {
        path: "/VERSION",
        label: "VERSION file",
        sev: "low",
    },
    Probe {
        path: "/version.txt",
        label: "version.txt",
        sev: "low",
    },
    Probe {
        path: "/README.md",
        label: "README",
        sev: "low",
    },
    Probe {
        path: "/INSTALL.txt",
        label: "INSTALL.txt",
        sev: "low",
    },
    Probe {
        path: "/crossdomain.xml",
        label: "crossdomain.xml",
        sev: "low",
    },
    Probe {
        path: "/clientaccesspolicy.xml",
        label: "clientaccesspolicy.xml",
        sev: "low",
    },
    Probe {
        path: "/wp-includes/wlwmanifest.xml",
        label: "WordPress manifest",
        sev: "low",
    },
    // ── INFO — baseline reachability ──────────────────────────────────────
    Probe {
        path: "/wp-login.php",
        label: "WordPress login",
        sev: "info",
    },
    Probe {
        path: "/login",
        label: "Login page",
        sev: "info",
    },
    Probe {
        path: "/signin",
        label: "Sign-in page",
        sev: "info",
    },
    Probe {
        path: "/cms",
        label: "CMS panel",
        sev: "info",
    },
    Probe {
        path: "/backend",
        label: "Backend panel",
        sev: "info",
    },
    Probe {
        path: "/portal",
        label: "Portal",
        sev: "info",
    },
    Probe {
        path: "/cpanel",
        label: "cPanel",
        sev: "info",
    },
    Probe {
        path: "/webmail",
        label: "Webmail",
        sev: "info",
    },
    Probe {
        path: "/actuator/health",
        label: "Spring health",
        sev: "info",
    },
    Probe {
        path: "/",
        label: "Root",
        sev: "info",
    },
    Probe {
        path: "/robots.txt",
        label: "robots.txt",
        sev: "info",
    },
    Probe {
        path: "/sitemap.xml",
        label: "Sitemap",
        sev: "info",
    },
];
