from packaging.version import Version, InvalidVersion
from schemas.vulnerability import AffectedProduct


class VersionComparator:

    @staticmethod
    def is_vulnerable(
        inventory_version: str,
        affected_product: AffectedProduct,
    ) -> bool:

        if not inventory_version:
            return True

        try:
            version = Version(inventory_version.strip())
        except InvalidVersion:
            return False

        if affected_product.version_start_including:
            try:
                if version < Version(affected_product.version_start_including):
                    return False
            except InvalidVersion:
                pass

        if affected_product.version_start_excluding:
            try:
                if version <= Version(affected_product.version_start_excluding):
                    return False
            except InvalidVersion:
                pass

        if affected_product.version_end_including:
            try:
                if version > Version(affected_product.version_end_including):
                    return False
            except InvalidVersion:
                pass

        if affected_product.version_end_excluding:
            try:
                if version >= Version(affected_product.version_end_excluding):
                    return False
            except InvalidVersion:
                pass

        return True
