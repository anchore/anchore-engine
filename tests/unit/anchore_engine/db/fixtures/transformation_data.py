single_cve = [
    {"source": "Bugtraq ID", "url": "http://www.securityfocus.com/bid/193"},
    {"source": "Snort Signature ID", "url": "http://www.snort.org/search/sid/1500?r=1"},
    {
        "source": "CVE ID",
        "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=1999-0449",
    },
]

single_cve_references = [(single_cve, ["CVE-1999-0449"])]

multiple_cve = [
    {
        "source": "Vendor Specific Advisory URL",
        "url": "https://www.mozilla.org/en-US/security/advisories/mfsa2018-08/",
    },
    {
        "source": "CVE ID",
        "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-5146",
    },
    {
        "source": "CVE ID",
        "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-5147",
    },
    {
        "source": "Bug Tracker",
        "url": "https://bugzilla.mozilla.org/show_bug.cgi?id=1446062",
    },
    {
        "source": "CVE ID",
        "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=2020-20412",
    },
    {
        "source": "Bug Tracker",
        "url": "https://github.com/stepmania/stepmania/issues/1890",
    },
]

multiple_cve_references = [
    (multiple_cve, ["CVE-2018-5146", "CVE-2018-5147", "CVE-2020-20412"])
]

no_cve = [
    {"source": "Vendor URL", "url": "http://tplink.com"},
    {
        "source": "Packet Storm",
        "url": "http://packetstormsecurity.com/files/124162/TPLINK-WR740N-WR740ND-Cross-Site-Request-Forgery.html",
    },
    {"source": "Exploit Database", "url": "http://www.exploit-db.com/exploits/29802"},
]

no_cve_references = [(no_cve, [])]
