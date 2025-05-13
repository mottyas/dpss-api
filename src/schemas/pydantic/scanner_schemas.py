
from dpss.models import ScanConfigSchema


class CreateScanConfigSchema(ScanConfigSchema):
    pass

class UpdateScanConfigSchema(ScanConfigSchema):
    pass

class ScanConfigResponseSchema(ScanConfigSchema):
    id: int
