"""
Модуль сервиса Сканера
"""

from pathlib import Path

from dpss.scanner import Scanner
from dpss.models import ScanConfigSchema, ReportModelSchema, ProjectConfigSchema, SoftComponentSchema
from dpss.dpss import DependencySecurityScanner
from dpss.sbom import GeneratorSBOM, ParserSBOM

from configs.settings import SERVICE_DB_PATH, DATA_DIR, VULNER_DB_PATH, VULNER_PACKAGES_DIR_PATH
from dbconnector.servicedb.servicedb import ServiceDB
from schemas.pydantic.scanner_schemas import CreateScanConfigSchema, UpdateScanConfigSchema
from models.scanner_models import (
    ScanConfigGetDTO,
    ReportFullDTO,
    ReportGetDTO,
    VulnerGetDTO,
    VulnersBasicsGetDTO,
    ScanConfigAddDTO,
    ProjectConfigAddDTO,
    ProjectConfigGetDTO,
    AddItemResponseDTO,
    ReportAddDTO,
    AffectedProjectDTO,
    VulnerBasicGetDTO,
)

class ScannerService:
    """Класс работы сервиса сканера"""

    def __init__(self) -> None:
        """Инициализация"""

        self.service_db_path = SERVICE_DB_PATH

    @staticmethod
    def get_config(config_id: int) -> ScanConfigGetDTO:
        """
        Метод получения конфигурации сканирования

        :param config_id: Идентификатор конфига
        :return: Конфигурация скнирования
        """

        with ServiceDB() as service_db:
            scan_config = service_db.get_scan_config(config_id)

        return scan_config

    @staticmethod
    def get_project_config(config_id: int) -> ProjectConfigGetDTO:
        """
        Метод получения конфигурации сканирования

        :param config_id: Идентификатор конфига
        :return: Конфигурация скнирования
        """

        with ServiceDB() as service_db:
            scan_config = service_db.get_project_config(config_id)

        return scan_config

    @staticmethod
    def get_all_configs() -> list[ScanConfigGetDTO]:
        """
        Метод получения всех конфигов сканирования

        :return: Список найденных конфигураций
        """

        with ServiceDB() as service_db:
            scan_configs = service_db.get_all_scan_configs()

        return scan_configs

    @staticmethod
    def add_config(create_config_schema: ScanConfigAddDTO) -> AddItemResponseDTO:
        """
        Метод добавления новой конфигурации

        :param create_config_schema: Новая конфигурация
        :return: Созданная конфигурация
        """

        with ServiceDB() as service_db:
            response = service_db.add_scan_config(create_config_schema)

        return response

    @staticmethod
    def add_proj_config(create_config_schema: ProjectConfigAddDTO) -> AddItemResponseDTO:
        """
        Метод добавления новой конфигурации

        :param create_config_schema: Новая конфигурация
        :return: Созданная конфигурация
        """

        with ServiceDB() as service_db:
            response = service_db.add_scan_project_config(create_config_schema)

        return response

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

    @staticmethod
    def delete_config(config_id: int) -> int:
        """
        Метод удаления конфигурации

        :param config_id: Идентификатор конфига
        """

        with ServiceDB() as service_db:
            deleted_id = service_db.delete_scan_config(config_id)

        return deleted_id

    def run_scanner(self, scan_config_id: int) -> AddItemResponseDTO:
        """
        Метод запуска сканирования зависимостей

        :param scan_config_id: Идентификатор конфигурации сканирования
        :return: Отчет по результатам сканирования
        """

        scan_config = self.get_config(config_id=scan_config_id)

        scan_conf_schema = ScanConfigSchema(
            host=scan_config.host,
            user=scan_config.user,
            secret=scan_config.secret,
            date=scan_config.date,
            name=scan_config.name,
            description=scan_config.description,
            projects=[
                ProjectConfigSchema(
                    name=project.name,
                    type=project.type,
                    dir=project.dir_path,
                    description=project.description,
                )
                for project in scan_config.projects
            ],
            port=int(scan_config.port),
            report_type='',
        )

        result_projects = []
        with ServiceDB() as service_db:
            scanner = Scanner(data_dir='/home/motya/malife/projects/depss-api/data', scan_config=scan_conf_schema)
            scanner.save_project_requirements()

            local_project_dirs = []
            for project in scan_config.projects:
                # local_project_dirs.append(Path('/home/motya/malife/projects/depss-api/data') / project.type / project.name)
                local_project_dir = Path('/home/motya/malife/projects/depss-api/data') / project.type / project.name
            # for local_project_dir in local_project_dirs:
                self.generate_sbom(local_project_dir)
                components = self.get_components_from_sbom(local_project_dir)
                vulnerable_software = service_db.find_vulnerable_software(components)
                projects = [
                    AffectedProjectDTO(
                        affected_id=affect_id,
                        project_config_id=project.id
                    ) for affect_id in vulnerable_software
                ]
                result_projects.extend(projects)

            report_data = ReportAddDTO(
                scan_config_id=scan_config_id,
                projects=result_projects,
            )
            report_id = service_db.save_report(report_data)
        return AddItemResponseDTO(created_item_id=report_id)

    @staticmethod
    def get_components_from_sbom(local_project_dir: Path) -> list[SoftComponentSchema]:
        """Метода парсинга SBOM данных"""

        return ParserSBOM(local_project_dir / 'sbom.json').get_components()


    @staticmethod
    def generate_sbom(local_project_dir: Path) -> None:
        """Метода генерации SBOM данных"""

        sbom_generator = GeneratorSBOM(
            source_path=local_project_dir,
            output_path=local_project_dir,
        )

        sbom_generator.generate_sbom(is_need_dump_file=True)

        # @staticmethod
        # def generate_sbom(local_project_dir: Path) -> None:
        #     """Метода генерации SBOM данных"""
        #
        #     sbom_generator = GeneratorSBOM(
        #         source_path=local_project_dir,
        #         output_path=local_project_dir,
        #     )
        #
        #     sbom_generator.generate_sbom(is_need_dump_file=True)

        # self.scanner = Scanner(scan_config=scan_conf_schema, data_dir='/data')
        # self.data_dir = '/data'
        # self.db_path = db_path
        # self.vulners_package_dir = vulners_package_dir
        # self.found_vulnerabilities = {}
        # self.report_type = scan_config.report_type
        # self.report = None

        # dpss = DependencySecurityScanner(
        #     scan_config=scan_conf_schema,
        #     db_path=VULNER_DB_PATH,
        #     vulners_package_dir=VULNER_PACKAGES_DIR_PATH,
        #     data_dir=Path(DATA_DIR),
        # )
        #
        # dpss.run()
        #
        # report_id = self.save_report(scan_config_id, dpss.report)
        #
        # return report_id

    # def save_report(self, scan_conf_id: int, report: ReportModelSchema) -> int:
    #     """
    #     Метод сохранения отчета
    #
    #     :param scan_conf_id:
    #     :param report:
    #     :return:
    #     """
    #
    #     report_dto = ReportAddDTO(
    #         scan_config_id=scan_conf_id,
    #         projects=[
    #             AffectedProjectDTO(
    #                 affected_id='',
    #                 project_config_id='',
    #             )
    #         ]
    #     )
    #
    #     with ServiceDB() as service_db:
    #         scan_config = service_db.save_report()
    #
    #     return scan_config


    @staticmethod
    def get_report_by_id(report_id: int) -> ReportFullDTO:
        """
        Метод получения отчета сканирования

        :param report_id: Идентификатор отчета
        :return: Отчет с результатами сканирования
        """
        with ServiceDB() as service_db:
            report = service_db.get_report(report_id)

        return report

    @staticmethod
    def get_reports() -> list[ReportGetDTO]:
        with ServiceDB() as service_db:
            reports = service_db.get_all_reports()

        return reports

    @staticmethod
    def get_vulner_data(vulner_id: str) -> VulnerGetDTO:
        with ServiceDB() as service_db:
            vulner_data = service_db.get_vulner_data(vulner_id)

        return vulner_data

    @staticmethod
    def get_vulners(page: int = 1, page_size: int = 20) -> VulnersBasicsGetDTO:
        with ServiceDB() as service_db:
            vulners_data = service_db.get_vulners(page, page_size)

        return vulners_data
