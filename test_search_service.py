from storage.search_service import SearchService

search = SearchService()

print("\n===== CVE SEARCH =====")
print(
    search.search_by_cve(
        "CVE-2024-33849"
    )
)

print("\n===== SEVERITY SEARCH =====")
print(
    search.search_by_severity(
        "MEDIUM"
    )
)

print("\n===== CWE SEARCH =====")
print(
    search.search_by_cwe(
        "CWE-321"
    )
)

print("\n===== FULL TEXT SEARCH =====")
print(
    search.full_text_search(
        "Cryptographic"
    )
)