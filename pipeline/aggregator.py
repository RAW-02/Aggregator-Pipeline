from collectors.mitre_collector import MITRECollector
from collectors.exploitdb_collector import ExploitDBDataCollector
from collectors.nvd_collector import NVDCollector
from normalizer.nvd_normalizer import NVDDataNormalizer
from search_optimizer.nvd_search import NVDSearchOptimizer
from collectors.kve_collector import KEVLookup
from collectors.epss_collector import EPSSLookup
from github_engine.main import github_engine

# MITRE INTEGRATION
# ---------------------------------------------------------------------
mitre = MITRECollector()
mitre_result = mitre.get_mitre_result("CVE-2021-33766")                                 # Input: CVE_Id
print(mitre_result)


# EXPLOIT-DB INTEGRATION
# ---------------------------------------------------------------------
exploitdb_collector = ExploitDBDataCollector()
exploitdb_result = exploitdb_collector.get_exploitdb_result("apache")                     # Input: CVE/Product/Vendor/CWE/Severity/Description
print(exploitdb_result)


# KEV (Known Exploited Vulnerabilities - lists CVEs that are actively being exploited in the wild. If a CVE is on this list, it represents an immediate threat)
# ---------------------------------------------------------------------
kev = KEVLookup()
kev_result = kev.is_known_exploited("CVE-2021-33766")                           # Input: CVE_Id
print("KVE: ", kev_result)


# EPSS (Exploit Prediction Scoring System - probability (from 0 to 1, or 0% to 100%) that a specific CVE will be exploited in the wild within the next 30 days. It is a tool designed to help teams predict which vulnerabilities attackers are likely to target next)
# ---------------------------------------------------------------------        
epss = EPSSLookup()
epss_result = epss.get_epss_score("CVE-2021-33766")                             # Input: CVE_Id
print("EPS score: ", epss_result)


# GITHUB ENGINE
# ---------------------------------------------------------------------        
github_result = github_engine("CVE-2021-33766")


# NVD INTEGRATION:   Input: CVE/Keyword/Product/Vendor/Platform/ExploitId/Exploit_Type/Description
# ---------------------------------------------------------------------            
# NVD search by CVE
nvd_collector = NVDCollector()
nvd_result = nvd_collector.get_nvd_by_cve("CVE-2021-44726")
print(nvd_result)



# NVD search by Keywork                             

# nvd_collector = NVDCollector()
# nvd_raw_data = nvd_collector.fetch_NVD_data("apache".strip())
# nvd_normalize_data = []
# normalize_nvd_data = NVDDataNormalizer()
# for item in nvd_raw_data.get("vulnerabilities",[]):
#     nvd_normalize_data.append(normalize_nvd_data.get_result(item))
# nvd_optimize_search = NVDSearchOptimizer()
# nvd_results = nvd_optimize_search.search_vulnerabilities(nvd_normalize_data)
# NVDSearchOptimizer.print_nvd_output(nvd_results)