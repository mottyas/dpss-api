"""
Модуль сервиса Сканера
"""

from pathlib import Path

from dpss.models import ScanConfigSchema, ReportModelSchema
from dpss.dpss import DependencySecurityScanner

from configs.settings import SERVICE_DB_PATH, DATA_DIR, VULNER_DB_PATH, VULNER_PACKAGES_DIR_PATH
from dbconnector.servicedb import ServiceDB
from schemas.pydantic.scanner_schemas import CreateScanConfigSchema, UpdateScanConfigSchema


class ScannerService:
    """Класс работы сервиса сканера"""

    def __init__(self) -> None:
        """Инициализация"""

        self.service_db_path = SERVICE_DB_PATH

    def get_config(self, config_id: int | str) -> ScanConfigSchema:
        """
        Метод получения конфигурации сканирования

        :param config_id: Идентификатор конфига
        :return: Конфигурация скнирования
        """

        is_id = True if isinstance(config_id, int) else False

        with ServiceDB(self.service_db_path) as service_db:
            scan_config = service_db.get_scan_config(config_id, is_id)

        return scan_config

    def get_all_configs(self) -> list[ScanConfigSchema]:
        """
        Метод получения всех конфигов сканирования

        :return: Список найденных конфигураций
        """

        with ServiceDB(self.service_db_path) as service_db:
            scan_configs = service_db.get_all_configs()

        return scan_configs

    def add_config(self, create_config_schema: CreateScanConfigSchema) -> CreateScanConfigSchema:
        """
        Метод добавления новой конфигурации

        :param create_config_schema: Новая конфигурация
        :return: Созданная конфигурация
        """

        with ServiceDB(self.service_db_path) as service_db:
            service_db.add_scan_config(create_config_schema)

        return create_config_schema

    def update_config(self, config_id: int | str, update_config_schema: UpdateScanConfigSchema) -> UpdateScanConfigSchema:
        """
        Метод обновления конфигурации

        :param config_id: Идентификатор конфигурации
        :param update_config_schema: Обновленная схема конфигурации
        :return: Обновленная конфигурация
        """

        is_id = True if isinstance(config_id, int) else False

        with ServiceDB(self.service_db_path) as service_db:
            scan_config = service_db.update_scan_config(config_id, update_config_schema, is_id)

        return scan_config

    def delete_config(self, config_id: int | str) -> None:
        """
        Метод удаления конфигурации

        :param config_id: Идентификатор конфига
        """

        is_id = True if isinstance(config_id, int) else False

        with ServiceDB(self.service_db_path) as service_db:
            service_db.delete_scan_config(config_id, is_id)

    def run_scanner(self, scan_config: ScanConfigSchema | None = None, scan_config_id: int | None = None) -> ReportModelSchema | None:
        """
        Метод запуска сканирования зависимостей

        :param scan_config: Конфигурация сканирования
        :param scan_config_id: Идентификатор конфигурации сканирования
        :return: Отчет по результатам сканирования
        """

        if not (scan_config_id or scan_config):
            return None

        if scan_config_id:
            scan_config = self.get_config(config_id=scan_config_id)

        dpss = DependencySecurityScanner(
            scan_config=scan_config,
            db_path=VULNER_DB_PATH,
            vulners_package_dir=VULNER_PACKAGES_DIR_PATH,
            data_dir=Path(DATA_DIR),
        )

        dpss.run()

        return dpss.report
