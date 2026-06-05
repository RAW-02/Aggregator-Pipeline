from collectors.mitre_collector import MITRECollector

from collectors.exploitdb_collector import ExploitDBDataCollector
from search_optimizer.exploitdb_search import ExploitDBSearchOptimizer

from collectors.nvd_collector import NVDCollector
from normalizer.nvd_normalizer import NVDDataNormalizer
from search_optimizer.nvd_search import NVDSearchOptimizer

from collectors.kve_collector import KEVLookup

from collectors.epss_collector import EPSSLookup

# MITRE INTEGRATION
# ---------------------------------------------------------------------
mitre_collector = MITRECollector()
mitre_data = mitre_collector.fetch_CVE_MITRE("CVE-2021-44228")                                # Input: CVE_ID

normalize_mitre_data = mitre_collector.search_mitre_record_by_cve(mitre_data)

MITRECollector.print_mitre_result(normalize_mitre_data)


# EXPLOIT-DB INTEGRATION
# ---------------------------------------------------------------------
exploitdb_collector = ExploitDBDataCollector()
exploitdb_raw_data = exploitdb_collector.fetch_exploits()

exploitdb_normalized_data = exploitdb_collector.normalize_exploitdb_data(exploitdb_raw_data)

exploitdb_optimize_search = ExploitDBSearchOptimizer()
exploitdb_result = exploitdb_optimize_search.search(exploitdb_normalized_data, "Apache")      # Input: CVE/Product/Vendor/CWE/Severity/Description

ExploitDBSearchOptimizer.print_exploitdb_output(exploitdb_result)


# NVD INTEGRATION
# ---------------------------------------------------------------------
user_input = input("Enter keyword: ").strip()                                                 # Input: CVE/Keyword/Product/Vendor/Platform/ExploitId/Exploit_Type/Description
nvd_collector = NVDCollector()
exploitdb_raw_data = nvd_collector.fetch_NVD_data(user_input)

nvd_normalize_data = []
normalize_nvd_data = NVDDataNormalizer()
for item in exploitdb_raw_data.get("vulnerabilities",[]):
    nvd_normalize_data.append(normalize_nvd_data.get_result(item))

nvd_optimize_search = NVDSearchOptimizer()
nvd_results = nvd_optimize_search.search_vulnerabilities(nvd_normalize_data)

NVDSearchOptimizer.print_nvd_output(nvd_results)


# KEV (Known Exploited Vulnerabilities - lists CVEs that are actively being exploited in the wild. If a CVE is on this list, it represents an immediate threat)
# ---------------------------------------------------------------------
kev = KEVLookup()
kev_result = kev.is_known_exploited("CVE-2021-44228")                           # Input: CVE_Id
print("KVE: ", kev_result)


# EPSS (Exploit Prediction Scoring System - probability (from 0 to 1, or 0% to 100%) that a specific CVE will be exploited in the wild within the next 30 days. It is a tool designed to help teams predict which vulnerabilities attackers are likely to target next)
# ---------------------------------------------------------------------        
epss = EPSSLookup()
epss_result = epss.get_epss_score("CVE-2021-44228")                             # Input: CVE_Id
print("EPS score: ", epss_result)