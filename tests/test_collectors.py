def test_import():
    import importlib

    assert importlib.import_module("collectors.nvd_collector")
