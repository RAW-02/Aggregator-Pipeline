from storage.opensearch_repository import OpenSearchRepository


def test_repository_import():
    repo = OpenSearchRepository()
    assert repo is not None