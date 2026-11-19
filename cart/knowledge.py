"""Knowledge base: severity, CWE / OWASP mapping and rule-based fixes.

Used by the rule-based remediation agent to attach a plain-English fix and a
reference patch to every proven finding.
"""

KB = {
    "sqli_auth_bypass": {
        "title": "SQL injection in login form (authentication bypass)",
        "severity": "critical", "cvss": 9.8, "cwe": "CWE-89", "owasp": "A03:2021 Injection",
        "impact": "Anyone can log in as any user, including the administrator, without a password.",
        "fix": "Use parameterised queries (placeholders) instead of building SQL with string formatting. "
               "Hash passwords (bcrypt/argon2) and add rate limiting on login.",
        "patch": 'row = db.execute(\n    "SELECT id, username, role FROM users WHERE username=? AND password=?",\n'
                 '    (username, password)).fetchone()',
    },
    "sqli": {
        "title": "SQL injection",
        "severity": "high", "cvss": 8.6, "cwe": "CWE-89", "owasp": "A03:2021 Injection",
        "impact": "Attacker can read data they should not see (e.g. hidden products, other tables).",
        "fix": "Use parameterised queries; never concatenate user input into SQL. Apply least-privilege DB accounts.",
        "patch": 'rows = db.execute(\n    "SELECT name, price FROM products WHERE hidden=0 AND name LIKE ?",\n'
                 '    (f"%{q}%",)).fetchall()',
    },
    "xss_reflected": {
        "title": "Reflected cross-site scripting (XSS)",
        "severity": "medium", "cvss": 6.1, "cwe": "CWE-79", "owasp": "A03:2021 Injection",
        "impact": "Attacker-supplied HTML/JS runs in the victim's browser (session theft, phishing).",
        "fix": "HTML-escape all user input on output (html.escape / template auto-escaping) and add a "
               "Content-Security-Policy header.",
        "patch": "shown = html.escape(q)",
    },
    "path_traversal": {
        "title": "Path traversal (arbitrary file read)",
        "severity": "high", "cvss": 7.5, "cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control",
        "impact": "Attacker can read files outside the intended folder (configs, keys, source code).",
        "fix": "Resolve the final path and verify it stays inside the allowed base directory; "
               "prefer a whitelist of file names. Do NOT just strip '../' (bypassable with '....//').",
        "patch": "target = (FILES_DIR / name).resolve()\nif FILES_DIR.resolve() not in target.parents:\n    abort(403)",
    },
    "idor": {
        "title": "Insecure direct object reference (IDOR)",
        "severity": "high", "cvss": 7.1, "cwe": "CWE-639", "owasp": "A01:2021 Broken Access Control",
        "impact": "A normal user can read other users' personal data (email, phone) by changing the id.",
        "fix": "Check on the server that the logged-in user owns the requested object (or is admin).",
        "patch": "if current_user.id != uid and current_user.role != 'admin':\n    return jsonify(error='forbidden'), 403",
    },
    "open_redirect": {
        "title": "Open redirect",
        "severity": "medium", "cvss": 4.7, "cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control",
        "impact": "Trusted domain can be abused to send victims to phishing sites.",
        "fix": "Only allow relative paths (starting with a single '/') or a whitelist of domains.",
        "patch": "if not (nxt.startswith('/') and not nxt.startswith('//')):\n    nxt = '/'",
    },
    "info_disclosure": {
        "title": "Sensitive information disclosure (debug endpoint)",
        "severity": "high", "cvss": 7.5, "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
        "impact": "Secret key leaked: attacker can forge session cookies and impersonate any user.",
        "fix": "Remove debug endpoints in production, rotate the leaked secret, load secrets from env vars.",
        "patch": "# delete the /debug route, or guard it:\nif not app.debug:\n    abort(404)",
    },
    "missing_security_headers": {
        "title": "Missing HTTP security headers",
        "severity": "low", "cvss": 3.1, "cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration",
        "impact": "No defence-in-depth against XSS, clickjacking and MIME sniffing.",
        "fix": "Add Content-Security-Policy, X-Frame-Options, X-Content-Type-Options and Referrer-Policy.",
        "patch": "@app.after_request\ndef sec_headers(r):\n    r.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                 "    r.headers['X-Frame-Options'] = 'DENY'\n    r.headers['X-Content-Type-Options'] = 'nosniff'\n    return r",
    },
    "privilege_escalation": {
        "title": "Privilege escalation to administrator (chained attack)",
        "severity": "critical", "cvss": 9.9, "cwe": "CWE-269", "owasp": "A01:2021 Broken Access Control",
        "impact": "Full admin control: list of all users and their emails exposed.",
        "fix": "Fix the root cause (login SQL injection). Add MFA for admin accounts and log admin logins.",
        "patch": "# fixed by the login SQL-injection patch",
    },
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
