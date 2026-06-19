from typing import Iterator


class CVESource:

    def get_all(self) -> Iterator[str]:
        """
        Yield CVE IDs one by one.

        Later this will be replaced by:
        - MITRE feeds
        - NVD feeds
        """

        raise NotImplementedError
