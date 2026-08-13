"""
CyberSagacity Tool Configuration — Chris Near's Rule Gathering Spec
Defines all 40 supported security scanning tools with their:
  - Supported languages (and language combination rules)
  - Required CSV fields
  - Severity mapping (tool-native → normalized abbreviation)
  - Classification mapping (where applicable)
  - Tool metadata (active/inactive, notes)

Each tool config generates the exact CSV columns Chris specified.
"""

TOOL_CONFIGS = {

    # -------------------------------------------------------------------------
    # 1. Adacore Codepeer
    # -------------------------------------------------------------------------
    "adacore_codepeer": {
        "display_name": "Adacore Codepeer",
        "languages": ["Ada"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "buffer_overflow.adb"},
            {"csv_header": "Message", "db_field": "title", "example": "array index check"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "120, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "H"},
        ],
        "severity_map": {
            "high": "H", "medium": "M", "low": "L",
            "information": "I", "info": "I", "warning": "W",
        },
    },

    # -------------------------------------------------------------------------
    # 2. Deque AXE
    # -------------------------------------------------------------------------
    "deque_axe": {
        "display_name": "Deque AXE",
        "languages": ["HTML"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "ARIA attributes must conform to valid names"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "serious": "Serious",
            "moderate": "Moderate", "minor": "Minor",
        },
    },

    # -------------------------------------------------------------------------
    # 3. Black Duck Coverity (formerly Synopsys)
    # -------------------------------------------------------------------------
    "synopsys_coverity": {
        "display_name": "Black Duck Coverity",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Objective-C",
                       "PHP", "Python", "Scala", "VisualBasic"],
        "language_notes": "C and C++ are combined; JavaScript, JavaScript Server Side, and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "type – subtype or just type"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79"},
            {"csv_header": "Impact", "db_field": "severity", "example": "H"},
        ],
        "severity_map": {"high": "H", "medium": "M", "low": "L"},
    },

    # -------------------------------------------------------------------------
    # 4. OpenText Fortify
    # -------------------------------------------------------------------------
    "opentext_fortify": {
        "display_name": "OpenText Fortify",
        "languages": ["Ada", "C/C++", "Csharp", "Java", "Javascript", "JSON",
                       "Objective-C", "PHP", "Python", "Scala", "SQL",
                       "Universal", "VisualBasic"],
        "language_notes": ("Csharp, VB.net, and ASP.net are combined; Java and JSP are combined; "
                           "JavaScript and Typescript are combined; SQL, PL/SQL, TSQL are combined; "
                           "VisualBasic, VBScript, and ASP are combined."),
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Command Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "77, 78, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "C"},
        ],
        "severity_map": {
            "critical": "C", "high": "H", "medium": "M", "low": "L",
        },
    },

    # -------------------------------------------------------------------------
    # 5. Checkmarx 9 (SAST)
    # -------------------------------------------------------------------------
    "checkmarx_9_sast": {
        "display_name": "Checkmarx 9 (SAST)",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Objective-C",
                       "PHP", "Python", "Scala", "SQL", "VisualBasic"],
        "language_notes": "C and C++ are combined; JavaScript, JavaScript Server Side, and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Angular_Client_DOM_XSS"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 6. Checkmarx One (SAST)
    # -------------------------------------------------------------------------
    "checkmarx_one_sast": {
        "display_name": "Checkmarx One (SAST)",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Objective-C",
                       "PHP", "Python", "Scala", "SQL", "VisualBasic"],
        "language_notes": "C and C++ are combined; JavaScript, JavaScript Server Side, and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Angular_Client_DOM_XSS"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 7. SonarQube
    # -------------------------------------------------------------------------
    "sonarqube": {
        "display_name": "SonarQube",
        "languages": ["C", "C++", "Csharp", "HTML", "Java", "JavaScript",
                       "Objective-C", "PHP", "Python", "Scala", "SQL",
                       "VisualBasic"],
        "language_notes": ("C and C++ are separate; HTML and CSS are combined; "
                           "JavaScript, TypeScript, and HTML are combined; "
                           "PL/SQL and SQL are combined; VisualBasic is VB.net + VB6."),
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "S116"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Field names should comply with a naming convention"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "315, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "B"},
            {"csv_header": "Classification", "db_field": "category", "example": "V"},
            {"csv_header": "Covered for AI Code Fix", "db_field": "metadata.ai_code_fix", "example": "Y/N"},
        ],
        "severity_map": {
            "blocker": "B", "critical": "C", "major": "M",
            "minor": "Mn", "information": "I", "info": "I",
        },
        "classification_map": {
            "vulnerability": "V", "security_hotspot": "S",
            "code_smell": "CS", "bug": "B",
        },
    },

    # -------------------------------------------------------------------------
    # 8. SpotBugs
    # -------------------------------------------------------------------------
    "spotbugs": {
        "display_name": "SpotBugs",
        "languages": ["Java"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name 1", "db_field": "title", "example": "BC: Equals method should not assume anything about the type of its argument"},
            {"csv_header": "Defect Name 2", "db_field": "rule_id", "example": "BC_EQUALS_METHOD_SHOULD_WORK_FOR_ALL_OBJECTS"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "315, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Severe"},
        ],
        "severity_map": {"1": "Severe", "2": "Moderate", "3": "Minor",
                         "high": "Severe", "medium": "Moderate", "low": "Minor"},
    },

    # -------------------------------------------------------------------------
    # 9. FindBugs (No longer active)
    # -------------------------------------------------------------------------
    "findbugs": {
        "display_name": "FindBugs",
        "languages": ["Java"],
        "language_notes": "No longer active.",
        "active": False,
        "fields": [
            {"csv_header": "Defect Name 1", "db_field": "title", "example": "BC: Equals method should not assume anything about the type of its argument"},
            {"csv_header": "Defect Name 2", "db_field": "rule_id", "example": "BC_EQUALS_METHOD_SHOULD_WORK_FOR_ALL_OBJECTS"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "315, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Severe"},
        ],
        "severity_map": {"1": "Severe", "2": "Moderate", "3": "Minor",
                         "high": "Severe", "medium": "Moderate", "low": "Minor"},
    },

    # -------------------------------------------------------------------------
    # 10. Facebook Infer
    # -------------------------------------------------------------------------
    "facebook_infer": {
        "display_name": "Facebook Infer",
        "languages": ["C/C++", "Java", "Objective-C"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "BUFFER_OVERRUN_L1"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 11. CppCheck
    # -------------------------------------------------------------------------
    "cppcheck": {
        "display_name": "CppCheck",
        "languages": ["C/C++"],
        "language_notes": "C and C++ are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Name", "db_field": "rule_id", "example": "CastIntegerToAddressAtReturn"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "315, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "E"},
        ],
        "severity_map": {
            "error": "E", "1": "E",
            "warning": "W", "2": "W",
            "style": "S", "3": "S",
            "portability": "P", "4": "P",
            "performance": "perf", "5": "perf",
            "information": "I", "info": "I", "6": "I",
        },
    },

    # -------------------------------------------------------------------------
    # 12. Bandit
    # -------------------------------------------------------------------------
    "bandit": {
        "display_name": "Bandit",
        "languages": ["Python"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "test_id", "db_field": "rule_id", "example": "B108"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "hardcoded_tmp_directory"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "H"},
        ],
        "severity_map": {"high": "H", "medium": "M", "low": "L"},
    },

    # -------------------------------------------------------------------------
    # 13. FindSecBugs
    # -------------------------------------------------------------------------
    "findsecbugs": {
        "display_name": "FindSecBugs",
        "languages": ["Java", "JavaScript"],
        "language_notes": "Java/JVM bytecode; Java ecosystem/framework vulnerability patterns. Security-focused SpotBugs plugin.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name 1", "db_field": "title", "example": "Untrusted servlet parameter"},
            {"csv_header": "Defect Name 2", "db_field": "rule_id", "example": "SERVLET_PARAMETER"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "315, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Severe"},
        ],
        "severity_map": {"1": "Severe", "2": "Moderate", "3": "Minor",
                         "high": "Severe", "medium": "Moderate", "low": "Minor"},
    },

    # -------------------------------------------------------------------------
    # 14. PMD
    # -------------------------------------------------------------------------
    "pmd": {
        "display_name": "PMD",
        "languages": ["Java", "JavaScript", "XML", "SQL"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "AvoidStringBufferField"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "usually none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "1"},
        ],
        "severity_map": {"1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
                         "critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"},
    },

    # -------------------------------------------------------------------------
    # 15. ESLint
    # -------------------------------------------------------------------------
    "eslint": {
        "display_name": "ESLint",
        "languages": ["JavaScript"],
        "language_notes": "JavaScript and Typescript are combined. Also supports @typescript-eslint, @react, @stylistic extensions.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "detect-unsafe-regex"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 16. Clang
    # -------------------------------------------------------------------------
    "clang": {
        "display_name": "Clang",
        "languages": ["C", "C++", "Objective-C"],
        "language_notes": "C and C++ are listed separately.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "core.CallAndMessage"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 17. Roguewave Klocwork
    # -------------------------------------------------------------------------
    "roguewave_klocwork": {
        "display_name": "Roguewave Klocwork",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Python"],
        "language_notes": "JavaScript, Typescript, and React are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "CS.ABV.EXCEPT"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "125, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "1"},
        ],
        "severity_map": {"1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
                         "critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"},
    },

    # -------------------------------------------------------------------------
    # 18. Tenable Nessus
    # -------------------------------------------------------------------------
    "tenable_nessus": {
        "display_name": "Tenable Nessus",
        "languages": ["Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "98033"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Login Form Defected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "319, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "C"},
        ],
        "severity_map": {
            "critical": "C", "high": "H", "medium": "M",
            "low": "L", "info": "I", "information": "I",
        },
    },

    # -------------------------------------------------------------------------
    # 19. Parasoft Insure++
    # -------------------------------------------------------------------------
    "parasoft_insure": {
        "display_name": "Parasoft Insure++",
        "languages": ["C/C++"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "FREE_NULL"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 20. Veracode SAST
    # -------------------------------------------------------------------------
    "veracode_sast": {
        "display_name": "Veracode SAST",
        "languages": ["Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Authentication Issues: Improper Authentication"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "287, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "0-5"},
        ],
        "severity_map": {
            "0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
            "critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1",
        },
    },

    # -------------------------------------------------------------------------
    # 21. PHP CodeSniffer
    # -------------------------------------------------------------------------
    "php_codesniffer": {
        "display_name": "PHP CodeSniffer",
        "languages": ["PHP"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Generic.Files.ByteOrderMark"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 22. PHPCS Security Audit
    # -------------------------------------------------------------------------
    "phpcs_security_audit": {
        "display_name": "PHPCS Security Audit",
        "languages": ["PHP"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Security.BadFunctions.Asserts"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 23. PHPMD
    # -------------------------------------------------------------------------
    "phpmd": {
        "display_name": "PHPMD",
        "languages": ["PHP"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "StaticAccess"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 24. Dlint
    # -------------------------------------------------------------------------
    "dlint": {
        "display_name": "Dlint",
        "languages": ["Python"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Number", "db_field": "rule_id", "example": "DUO101"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "YieldReturnStatementLinter"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 25. Whitehat
    # -------------------------------------------------------------------------
    "whitehat": {
        "display_name": "Whitehat",
        "languages": ["Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "Access.Administration.Interface"},
            {"csv_header": "Description", "db_field": "description", "example": "Application Misconfiguration: Exposed Axis Administration Servlet"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 26. Flawfinder (No longer active)
    # -------------------------------------------------------------------------
    "flawfinder": {
        "display_name": "Flawfinder",
        "languages": ["C/C++"],
        "language_notes": "No longer active.",
        "active": False,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "AddAccessAllowedAce"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "732"},
            {"csv_header": "Severity", "db_field": "severity", "example": "1-5"},
        ],
        "severity_map": {"1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
                         "critical": "5", "high": "4", "medium": "3", "low": "2", "info": "1"},
    },

    # -------------------------------------------------------------------------
    # 27. Mend
    # -------------------------------------------------------------------------
    "mend": {
        "display_name": "Mend",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Objective-C",
                       "PHP", "Python", "SQL", "VisualBasic"],
        "language_notes": "JavaScript and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {"high": "High", "medium": "Medium", "low": "Low"},
    },

    # -------------------------------------------------------------------------
    # 28. Snyk Code (SAST)
    # -------------------------------------------------------------------------
    "snyk_code_sast": {
        "display_name": "Snyk Code (SAST)",
        "languages": ["Csharp", "Java", "Javascript", "PHP", "Python", "C/C++", "Go", "Ruby", "Scala", "Swift"],
        "language_notes": "Keep separate from Snyk Open Source/SCA, IaC and Container. Some languages/capabilities are limited or early access.",
        "active": True,
        "fields": [
            {"csv_header": "Snyk Defect No", "db_field": "rule_id", "example": ""},
            {"csv_header": "Snyk Defect Name", "db_field": "title", "example": "Hardcoded Secret"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "547, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 29. GitLab
    # -------------------------------------------------------------------------
    "gitlab": {
        "display_name": "GitLab",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "PHP",
                       "Python", "Scala", "Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "title", "example": "nodejs_scan.javascript-headers-rule-generic_cors"},
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "gitlab.nodejs_scan.javascript-headers-rule-generic_cors"},
            {"csv_header": "Platform", "db_field": "metadata.platform", "example": "nodejs"},
            {"csv_header": "Open Source Tool", "db_field": "metadata.oss_tool", "example": "nodejsscan"},
            {"csv_header": "Gitlab Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Gitlab Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 30. GitHub
    # -------------------------------------------------------------------------
    "github": {
        "display_name": "GitHub",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Python", "Swift"],
        "language_notes": "C and C++ are combined; Java and Kotlin are combined; JavaScript and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name 1", "db_field": "title", "example": "cpp/new-delete-array-mismatch"},
            {"csv_header": "Defect Name 2", "db_field": "description", "example": "'new' object freed with 'delete[]'"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "118, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Error"},
            {"csv_header": "Security Severity", "db_field": "metadata.security_severity", "example": "8.2 or 9.3"},
        ],
        "severity_map": {
            "error": "Error", "warning": "Warning",
            "recommendation": "Recommendation",
            "critical": "Error", "high": "Error", "medium": "Warning", "low": "Recommendation",
        },
    },

    # -------------------------------------------------------------------------
    # 31. Semgrep
    # -------------------------------------------------------------------------
    "semgrep": {
        "display_name": "Semgrep",
        "languages": ["C/C++", "Csharp", "HTML", "Java", "JavaScript", "JSON",
                       "PHP", "Python", "Scala", "Universal", "XML"],
        "language_notes": "JavaScript and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "getpw-1"},
            {"csv_header": "Defect ID", "db_field": "metadata.defect_id", "example": "gitlab.flawfinder.getpw-1"},
            {"csv_header": "Open Source Tool", "db_field": "metadata.oss_tool", "example": "flawfinder"},
            {"csv_header": "Gitlab Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Gitlab Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 32. JFrog
    # -------------------------------------------------------------------------
    "jfrog": {
        "display_name": "JFrog",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Python"],
        "language_notes": "JavaScript and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "cpp-cgi-xss"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
            {"csv_header": "Top 10 Mapping", "db_field": "owasp_ids", "example": "A03, A05, can be none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 33. PyLint
    # -------------------------------------------------------------------------
    "pylint": {
        "display_name": "PyLint",
        "languages": ["Python"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "PY3.C0103"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "1-3"},
            {"csv_header": "Category", "db_field": "category", "example": "Basic, Refactoring, Classes, etc"},
            {"csv_header": "Description", "db_field": "description", "example": "Invalid name"},
            {"csv_header": "Enabled by Default", "db_field": "metadata.enabled_default", "example": "FALSE/TRUE"},
        ],
        "severity_map": {"1": "1", "2": "2", "3": "3",
                         "high": "1", "medium": "2", "low": "3"},
    },

    # -------------------------------------------------------------------------
    # 34. Security Code Scan
    # -------------------------------------------------------------------------
    "security_code_scan": {
        "display_name": "Security Code Scan",
        "languages": ["Csharp"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SCS0001 – Command Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "78 or none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 35. nodejs_scan
    # -------------------------------------------------------------------------
    "nodejs_scan": {
        "display_name": "nodejs_scan",
        "languages": ["Javascript"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "crypto.sha1_hash.sha1_hash"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 36. njsscan
    # -------------------------------------------------------------------------
    "njsscan": {
        "display_name": "njsscan",
        "languages": ["JavaScript"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "crypto.sha1_hash.sha1_hash"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 37. mobsf
    # -------------------------------------------------------------------------
    "mobsf": {
        "display_name": "mobsf",
        "languages": ["Java"],
        "language_notes": "Java and Android are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "crypto.sha1_hash.sha1_hash"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 38. npm
    # -------------------------------------------------------------------------
    "npm": {
        "display_name": "npm",
        "languages": ["Javascript"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "crypto.sha1_hash.sha1_hash"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "ERROR"},
            {"csv_header": "Level", "db_field": "metadata.level", "example": "High"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 39. OWASP Zap
    # -------------------------------------------------------------------------
    "owasp_zap": {
        "display_name": "OWASP Zap",
        "languages": ["Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "6-1"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Path Traversal"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "22 or none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
            {"csv_header": "Type", "db_field": "metadata.scan_type", "example": "Passive or Active or Tool"},
            {"csv_header": "WASC", "db_field": "metadata.wasc", "example": "48"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "informational": "Informational", "info": "Informational",
        },
    },

    # -------------------------------------------------------------------------
    # 40. Wallarm API
    # -------------------------------------------------------------------------
    "wallarm_api": {
        "display_name": "Wallarm API",
        "languages": ["Universal"],
        "language_notes": None,
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "DdoS attacks"},
            {"csv_header": "Wallarm Code", "db_field": "metadata.wallarm_code", "example": "ddos"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # =========================================================================
    # V3 ADDITIONS — Chris Near's SATriage Support spreadsheet (Aug 2026)
    # Tools added to align with the updated AST Tools list.
    # =========================================================================

    # -------------------------------------------------------------------------
    # 41. GitLab DAST
    # -------------------------------------------------------------------------
    "gitlab_dast": {
        "display_name": "GitLab DAST",
        "languages": ["Universal"],
        "language_notes": "DAST is language-agnostic; scans running web applications and APIs.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "dast.xss"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Cross-Site Scripting"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info", "informational": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 42. GitLab Advanced SAST
    # -------------------------------------------------------------------------
    "gitlab_advanced_sast": {
        "display_name": "GitLab Advanced SAST",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "PHP", "Python", "Scala"],
        "language_notes": "Cross-file/cross-function taint analysis. Distinguishable from legacy GitLab SAST.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "title", "example": "nodejs_scan.javascript-headers-rule-generic_cors"},
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "gitlab-advanced-sast.xss"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "ERROR"},
        ],
        "severity_map": {
            "error": "ERROR", "warning": "WARNING", "info": "INFO",
            "critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO",
        },
    },

    # -------------------------------------------------------------------------
    # 43. GitHub CodeQL
    # -------------------------------------------------------------------------
    "codeql": {
        "display_name": "GitHub CodeQL",
        "languages": ["C/C++", "Csharp", "Go", "Java", "JavaScript", "Python", "Ruby", "Rust", "Swift"],
        "language_notes": "C and C++ are combined; Java and Kotlin are combined; JavaScript and Typescript are combined.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name 1", "db_field": "title", "example": "cpp/new-delete-array-mismatch"},
            {"csv_header": "Defect Name 2", "db_field": "description", "example": "'new' object freed with 'delete[]'"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "118, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Error"},
            {"csv_header": "Security Severity", "db_field": "metadata.security_severity", "example": "8.2 or 9.3"},
        ],
        "severity_map": {
            "error": "Error", "warning": "Warning",
            "recommendation": "Recommendation",
            "critical": "Error", "high": "Error", "medium": "Warning", "low": "Recommendation",
        },
    },

    # -------------------------------------------------------------------------
    # 44. Checkmarx DAST
    # -------------------------------------------------------------------------
    "checkmarx_dast": {
        "display_name": "Checkmarx DAST",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic; scans running web applications and APIs.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 45. Checkmarx API Security
    # -------------------------------------------------------------------------
    "checkmarx_api": {
        "display_name": "Checkmarx API Security",
        "languages": ["Universal"],
        "language_notes": "API discovery and API-specific findings; integrates SAST and DAST observations.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "API_BOLA"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "639, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 46. Mend DAST
    # -------------------------------------------------------------------------
    "mend_dast": {
        "display_name": "Mend DAST",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic; scans running applications and APIs.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
        },
    },

    # -------------------------------------------------------------------------
    # 47. Veracode DAST
    # -------------------------------------------------------------------------
    "veracode_dast": {
        "display_name": "Veracode Dynamic Analysis / DAST",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic; scans web applications and APIs.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "CWE-79 XSS"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info", "informational": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 48. Contrast Assess (IAST)
    # -------------------------------------------------------------------------
    "contrast_assess": {
        "display_name": "Contrast Assess",
        "languages": ["Java", "Csharp", "JavaScript", "Python"],
        "language_notes": "Agent/instrumentation-based IAST. Runtime data-flow analysis with active verification.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "sql-injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 49. Contrast Scan (SAST)
    # -------------------------------------------------------------------------
    "contrast_scan": {
        "display_name": "Contrast Scan",
        "languages": ["Java", "Csharp", "JavaScript", "Python"],
        "language_notes": "Contrast's SAST capability, separate from Assess/IAST.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "sql-injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 50. Acunetix (Invicti)
    # -------------------------------------------------------------------------
    "acunetix": {
        "display_name": "Acunetix",
        "languages": ["Universal"],
        "language_notes": "DAST; language-agnostic. CVE-based vulnerability scanning.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "CVE-2021-44228"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Log4Shell"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "502, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 51. Invicti
    # -------------------------------------------------------------------------
    "invicti": {
        "display_name": "Invicti",
        "languages": ["Universal"],
        "language_notes": "DAST-first platform with API discovery/testing and proof-based validation. CVE-based.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "CVE-2021-44228"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Log4Shell"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "502, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 52. Burp Suite DAST
    # -------------------------------------------------------------------------
    "burp_suite_dast": {
        "display_name": "Burp Suite DAST",
        "languages": ["Universal"],
        "language_notes": "Enterprise automated Burp Scanner with modern API scanning support.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 53. Burp Suite Professional Scanner
    # -------------------------------------------------------------------------
    "burp_suite_pro": {
        "display_name": "Burp Suite Professional Scanner",
        "languages": ["Universal"],
        "language_notes": "Burp Professional results can enter workflows independently of Burp Suite DAST.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 54. HCL AppScan 360
    # -------------------------------------------------------------------------
    "hcl_appscan_360": {
        "display_name": "HCL AppScan 360",
        "languages": ["Universal"],
        "language_notes": "Platform: SAST / DAST / API. Static languages plus language-agnostic dynamic/API scanning.",
        "active": False,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 55. HCL AppScan Source (SAST)
    # -------------------------------------------------------------------------
    "hcl_appscan_source": {
        "display_name": "HCL AppScan Source",
        "languages": ["Universal"],
        "language_notes": "Multi-language static analysis; support varies by release.",
        "active": False,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL_Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 56. HCL AppScan Standard (DAST)
    # -------------------------------------------------------------------------
    "hcl_appscan_standard": {
        "display_name": "HCL AppScan Standard",
        "languages": ["Universal"],
        "language_notes": "Major enterprise DAST scanner. Language-agnostic; web applications and APIs.",
        "active": False,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "high": "High", "medium": "Medium", "low": "Low",
            "information": "Information", "info": "Information",
        },
    },

    # -------------------------------------------------------------------------
    # 57. Black Duck Continuous Dynamic (DAST)
    # -------------------------------------------------------------------------
    "blackduck_dynamic": {
        "display_name": "Black Duck Continuous Dynamic",
        "languages": ["Universal"],
        "language_notes": "Production-safe DAST with continuous scanning/verification. Successor to WhiteHat Dynamic.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 58. Black Duck Seeker (IAST)
    # -------------------------------------------------------------------------
    "blackduck_seeker": {
        "display_name": "Black Duck Seeker",
        "languages": ["Java", "Csharp", "JavaScript", "PHP", "Python", "Ruby"],
        "language_notes": "True IAST. Instruments running applications and performs runtime/data-flow analysis.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL_Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 59. Black Duck Polaris
    # -------------------------------------------------------------------------
    "blackduck_polaris": {
        "display_name": "Black Duck Polaris",
        "languages": ["Universal"],
        "language_notes": "Platform: SAST / DAST / SCA. Multiple languages; scanner dependent.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "SQL_Injection"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "89, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 60. Perforce Klocwork Static Analysis
    # -------------------------------------------------------------------------
    "perforce_klocwork": {
        "display_name": "Perforce Klocwork Static Analysis",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Python", "Kotlin", "Rust"],
        "language_notes": "JavaScript, Typescript, and React are combined. Enterprise static analysis with security rules.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "CS.ABV.EXCEPT"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "125, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "1"},
        ],
        "severity_map": {"1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
                         "critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"},
    },

    # -------------------------------------------------------------------------
    # 61. JFrog SAST
    # -------------------------------------------------------------------------
    "jfrog_sast": {
        "display_name": "JFrog SAST",
        "languages": ["C/C++", "Csharp", "Java", "JavaScript", "Python"],
        "language_notes": "JavaScript and Typescript are combined. Dedicated cross-file semantic SAST engine.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "cpp-cgi-xss"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
            {"csv_header": "Top 10 Mapping", "db_field": "owasp_ids", "example": "A03, A05, can be none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 62. Gitleaks (Secrets)
    # -------------------------------------------------------------------------
    "gitleaks": {
        "display_name": "Gitleaks",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic; scans Git repositories, files, and history for secrets.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "aws-access-token"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "798, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 63. Grype (SCA / Container)
    # -------------------------------------------------------------------------
    "grype": {
        "display_name": "Grype",
        "languages": ["Universal"],
        "language_notes": "CVE-based. Container images, filesystems, SBOMs, packages.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "CVE-2021-44228"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Log4Shell"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "502, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "negligible": "Negligible", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 64. Joern (Code Property Graph)
    # -------------------------------------------------------------------------
    "joern": {
        "display_name": "Joern",
        "languages": ["C/C++", "Java", "JavaScript", "Python", "Kotlin"],
        "language_notes": "Code Property Graph analyzer. Vulnerability research and data flow analysis.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "buffer-overflow"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "120, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 65. OSV-Scanner (SCA)
    # -------------------------------------------------------------------------
    "osv_scanner": {
        "display_name": "OSV-Scanner",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic through package manifests, lockfiles, SBOMs. CVE-based.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "CVE-2021-44228"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Log4Shell"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "502, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 66. TruffleHog OSS (Secrets)
    # -------------------------------------------------------------------------
    "trufflehog": {
        "display_name": "TruffleHog OSS",
        "languages": ["Universal"],
        "language_notes": "Language-agnostic; scans repositories, filesystems, and supported data sources.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "aws-access-token"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "798, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 67. ErrorProne (SAST)
    # -------------------------------------------------------------------------
    "errorprone": {
        "display_name": "ErrorProne",
        "languages": ["Java"],
        "language_notes": "Google's Java bug pattern analyzer. Compile-time error detection.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "NullAway"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "none"},
        ],
        "severity_map": {},
    },

    # -------------------------------------------------------------------------
    # 68. StackHawk (DAST)
    # -------------------------------------------------------------------------
    "stackhawk": {
        "display_name": "StackHawk",
        "languages": ["Universal"],
        "language_notes": "DAST; language-agnostic. CI/CD integrated dynamic application security testing.",
        "active": True,
        "fields": [
            {"csv_header": "Defect Name", "db_field": "rule_id", "example": "XSS_Reflected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "79, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "High"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },

    # -------------------------------------------------------------------------
    # 69. Tenable Web App Scanning (DAST)
    # -------------------------------------------------------------------------
    "tenable_was": {
        "display_name": "Tenable Web App Scanning",
        "languages": ["Universal"],
        "language_notes": "Automated DAST and API scanning. Distinct from Nessus.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "98033"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Login Form Defected"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "319, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "C"},
        ],
        "severity_map": {
            "critical": "C", "high": "H", "medium": "M",
            "low": "L", "info": "I", "information": "I",
        },
    },

    # -------------------------------------------------------------------------
    # 70. Snyk Open Source (SCA)
    # -------------------------------------------------------------------------
    "snyk_oss_sca": {
        "display_name": "Snyk Open Source (SCA)",
        "languages": ["Universal"],
        "language_notes": "CVE-based. Supply chain and dependency security.",
        "active": True,
        "fields": [
            {"csv_header": "Defect ID", "db_field": "rule_id", "example": "CVE-2021-44228"},
            {"csv_header": "Defect Name", "db_field": "title", "example": "Log4Shell"},
            {"csv_header": "CWE Mapping", "db_field": "cwe_ids", "example": "502, can be none"},
            {"csv_header": "Severity", "db_field": "severity", "example": "Critical"},
        ],
        "severity_map": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
    },
}


def get_all_tools():
    """Return all tool configs."""
    return TOOL_CONFIGS


def get_tool(tool_key):
    """Return a single tool config by key."""
    return TOOL_CONFIGS.get(tool_key)


def get_active_tools():
    """Return only active (non-deprecated) tools."""
    return {k: v for k, v in TOOL_CONFIGS.items() if v.get("active", True)}


def get_tool_summary():
    """Return a summary list for the dashboard."""
    summary = []
    for key, cfg in TOOL_CONFIGS.items():
        summary.append({
            "key": key,
            "display_name": cfg["display_name"],
            "languages": cfg["languages"],
            "language_notes": cfg.get("language_notes"),
            "active": cfg.get("active", True),
            "field_count": len(cfg["fields"]),
            "language_count": len(cfg["languages"]),
            "csv_headers": [f["csv_header"] for f in cfg["fields"]],
            "has_severity": bool(cfg.get("severity_map")),
        })
    return summary


def map_severity(tool_key, raw_severity):
    """Map a raw severity value to the tool's normalized abbreviation."""
    cfg = TOOL_CONFIGS.get(tool_key)
    if not cfg or not raw_severity:
        return raw_severity or ""
    sev_map = cfg.get("severity_map", {})
    return sev_map.get(str(raw_severity).lower(), raw_severity)


def get_csv_headers(tool_key):
    """Return the CSV column headers for a given tool."""
    cfg = TOOL_CONFIGS.get(tool_key)
    if not cfg:
        return []
    return [f["csv_header"] for f in cfg["fields"]]
