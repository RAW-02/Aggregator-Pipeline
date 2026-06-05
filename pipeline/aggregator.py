from collectors.mitre_collector import MITRECollector

from collectors.exploitdb_collector import ExploitDBDataCollector
from normalizer.exploitdb_normalizer import ExploitDBDataNormalizer
from search_optimizer.exploitdb_search import ExploitDBSearchOptimizer

from collectors.nvd_collector import NVDCollector
from normalizer.nvd_normalizer import NVDDataNormalizer
from search_optimizer.nvd_search import NVDSearchOptimizer



# MITRE INTEGRATION
# ---------------------------------------------------------------------
mitre_collector = MITRECollector()
mitre_data = mitre_collector.fetch_CVE_MITRE("CVE-2021-44228")    # user input
normalize_mitre_data = mitre_collector.normalize_mitre_raw_data(mitre_data)

MITRECollector.print_mitre_result(normalize_mitre_data)


# EXPLOIT-DB INTEGRATION
# ---------------------------------------------------------------------
exploitdb_collector = ExploitDBDataCollector()
exploitdb_raw_data = exploitdb_collector.fetch_exploits()

normalize_exploitdb_data = ExploitDBDataNormalizer()
exploitdb_normalized_data = normalize_exploitdb_data.process(exploitdb_raw_data)

exploitdb_optimize_search = ExploitDBSearchOptimizer()
exploitdb_result = exploitdb_optimize_search.search(exploitdb_normalized_data, "Apache")      # user input

ExploitDBSearchOptimizer.print_exploitdb_output(exploitdb_result)


# NVD INTEGRATION
# ---------------------------------------------------------------------
user_input = input("Enter keyword: ").strip()                   # user input
nvd_collector = NVDCollector()
exploitdb_raw_data = nvd_collector.fetch_NVD_data(user_input)

nvd_normalize_data = []
normalize_nvd_data = NVDDataNormalizer()
for item in exploitdb_raw_data.get("vulnerabilities",[]):
    nvd_normalize_data.append(normalize_nvd_data.get_result(item))

nvd_optimize_search = NVDSearchOptimizer()
nvd_results = nvd_optimize_search.search_vulnerabilities(nvd_normalize_data)

NVDSearchOptimizer.print_nvd_output(nvd_results)
