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
    # 3. Synopsys Coverity
    # -------------------------------------------------------------------------
    "synopsys_coverity": {
        "display_name": "Synopsys Coverity",
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
        "languages": ["JavaScript"],
        "language_notes": None,
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
        "languages": ["Csharp", "Java", "Javascript", "PHP", "Python"],
        "language_notes": None,
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
