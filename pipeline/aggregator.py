from collectors.mitre_collector import MITRECollector
from search_optimizer.exploitdb_search import SearchService
from normalizer.exploitdb_normalizer import ExploitDBProcessor
from collectors.exploitdb_collector import ExploitDBFetcher



# EXPLOIT-DB INTEGRATION
exploitdb_collector = ExploitDBFetcher()
exploitdb_raw_data = exploitdb_collector.fetch_exploits()

processor = ExploitDBProcessor()
processed_data = processor.process(exploitdb_raw_data)

search_service = SearchService()
exploit_data = search_service.search(processed_data, "Apache")
ExploitDBFetcher.printOutput(exploit_data)


# MITRE INTEGRATION
mitre_collector = MITRECollector()
mitre_data = mitre_collector.fetch_cve("CVE-2021-44228")
print(mitre_data)
