from collectors.nvd_collector import NVDCollector
from collectors.epss_collector import EPSSCollector

def test_nvd_import():
    collector = NVDCollector()
    assert collector is not None


def test_epss_import():
    collector = EPSSCollector()
    assert collector is not None