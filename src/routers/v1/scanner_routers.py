"""
Модуль маршрутов для работы сканера
"""

from fastapi import (
    APIRouter,
    Depends,
)

from dpss.models import ScanConfigSchema, ReportModelSchema

from models.scanner_models import (
    ScanConfigGetDTO,
    ReportFullDTO,
    ReportGetDTO,
    VulnerGetDTO,
    VulnerBasicGetDTO,
)
from services.scanner_service import ScannerService
from schemas.pydantic.scanner_schemas import (
    CreateScanConfigSchema,
    UpdateScanConfigSchema,
)

scanner_router = APIRouter(prefix="/v1/scan", tags=["scan_configs"])
"""
Эндпоинты для управления задачами
"""


@scanner_router.get(path='/confs/id/{item_id}', response_model=ScanConfigGetDTO)
def get_scan_config_by_id(item_id: int, scanner_service: ScannerService = Depends()):
    return scanner_service.get_config(item_id)


# @scanner_router.get(path='/confs/name/{name}', response_model=ScanConfigSchema)
# def get_scan_config_by_name(name: str, scanner_service: ScannerService = Depends()):
#     return scanner_service.get_config(name)


@scanner_router.delete(path='/confs/id/{item_id}', response_model=ScanConfigSchema)
def delete_scan_config_by_id(item_id: int, scanner_service: ScannerService = Depends()):
    return scanner_service.delete_config(item_id)


# @scanner_router.delete(path='/confs/name/{name}', response_model=ScanConfigSchema)
# def delete_scan_config_by_name(name: str, scanner_service: ScannerService = Depends()):
#     return scanner_service.delete_config(name)


@scanner_router.post(path='/confs/', response_model=ScanConfigSchema)
def make_new_scan_config(
        scan_conf_schema: CreateScanConfigSchema,
        scanner_service: ScannerService = Depends(),
):
    return scanner_service.add_config(scan_conf_schema)


@scanner_router.get(path='/confs/all', response_model=list[ScanConfigGetDTO])
def get_all_scan_configs(scanner_service: ScannerService = Depends()):
    return scanner_service.get_all_configs()


@scanner_router.put(path='/confs/id/{item_id}', response_model=ScanConfigSchema)
def update_scan_config_by_id(
        item_id: int,
        scan_conf_schema: UpdateScanConfigSchema,
        scanner_service: ScannerService = Depends(),
):
    return scanner_service.update_config(item_id, scan_conf_schema)

@scanner_router.get(path='/reports/id/{item_id}', response_model=ReportFullDTO)
def get_report_by_id(item_id: int, scanner_service: ScannerService = Depends()):
    return scanner_service.get_report_by_id(item_id)

@scanner_router.get(path='/reports', response_model=list[ReportGetDTO])
def get_report_by_id(scanner_service: ScannerService = Depends()):
    return scanner_service.get_reports()

@scanner_router.get(path='/vulners/{item_id}', response_model=VulnerGetDTO)
def get_vulner_by_id(item_id: str, scanner_service: ScannerService = Depends()):
    return scanner_service.get_vulner_data(item_id)

@scanner_router.get(path='/vulners', response_model=list[VulnerBasicGetDTO])
def get_vulner_by_id(page: int = 1, page_size = 20, scanner_service: ScannerService = Depends()):
    return scanner_service.get_vulners(page, page_size)


# @scanner_router.put(path='/confs/name/{name}', response_model=ScanConfigSchema)
# def update_scan_config_by_name(
#         name: str,
#         scan_conf_schema: UpdateScanConfigSchema,
#         scanner_service: ScannerService = Depends()
# ):
#     return scanner_service.update_config(name, scan_conf_schema)


@scanner_router.post(path='/run', response_model=ReportModelSchema)
def run_scanner(
        scan_conf_schema: ScanConfigSchema,
        scanner_service: ScannerService = Depends(),
):
    return scanner_service.run_scanner(scan_config=scan_conf_schema)


@scanner_router.post(path='/run/{scan_config_id}', response_model=ReportModelSchema)
def run_scanner_by_id(
        scan_config_id: int,
        scanner_service: ScannerService = Depends(),
):
    return scanner_service.run_scanner(scan_config_id=scan_config_id)
