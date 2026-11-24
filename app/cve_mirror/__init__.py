"""Local mirror of the NVD and CVE.org (CVE List) vulnerability databases.

Scans resolve CVEs against this mirror instead of querying NVD per service:
    sync.py      pulls NVD JSON 2.0 feeds + CVEProject/cvelistV5 into the mirror
    query.py     product/version -> CVE matching, evaluated locally
    parse.py     upstream record -> mirror rows
    versions.py  version-range comparison
"""
