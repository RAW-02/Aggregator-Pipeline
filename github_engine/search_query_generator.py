def generate_search_queries(user_query, query_type, alias_info=None):
    queries = set()
    queries.add(user_query)

    if query_type == "cve":
        queries.add(
            f"{user_query} exploit"
        )

        queries.add(
            f"{user_query} poc"
        )

        queries.add(
            f"{user_query} scanner"
        )

    elif query_type == "product":
        queries.add(
            f"{user_query} exploit"
        )

        queries.add(
            f"{user_query} poc"
        )

        queries.add(
            f"{user_query} rce"
        )

    elif query_type == "category":
        queries.add(
            f"{user_query} exploit"
        )

        queries.add(
            f"{user_query} poc"
        )
    
    elif query_type == "product_or_vulnerability":
        queries.add(
            f"{user_query} exploit"
        )

        queries.add(
            f"{user_query} poc"
        )

        queries.add(
            f"{user_query} scanner"
        )

    if alias_info:
        cve = alias_info.get("cve")

        if cve:
            queries.add(cve)

            queries.add(
                f"{cve} exploit"
            )

            queries.add(
                f"{cve} poc"
            )

    return list(queries)