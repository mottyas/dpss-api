"""
Модуль работы с сервисной базой данных
"""

from sqlalchemy import select, update, delete
from sqlalchemy.orm import Session, sessionmaker, joinedload
from sqlalchemy.engine.base import Engine

from dbconnector.servicedb.functions import get_db_engine
from dbconnector.servicedb.models import (
    Base,
    ScanConfigORM,
    ProjectConfigORM,
    ReportORM,
    AffectedProjectsORM,
    ReportProjectORM,
    VulnerORM,
    AffectedORM,
)
from models.scanner_models import (
    ScanConfigAddDTO,
    ScanConfigGetDTO,
    ProjectConfigAddDTO,
    ProjectConfigGetDTO,
    ReportProjectAffectsDTO,
    ReportGetDTO,
    ReportAddDTO,
    AffectedProjectDTO,
    ReportFullDTO,
    ReportProjectDTO,
    VulnerGetDTO,
    ReferenceGetDTO,
    RatingGetDTO,
    AffectedGetDTO,
    ReportAffectDTO,
    VulnerBasicGetDTO,
)


class ServiceDB:
    """Класс работы с базой данных сервера"""

    def __init__(self, engine: Engine = get_db_engine()) -> None:
        """
        Инициализация класса

        :param engine: Движок базы данных
        """

        self.engine = engine
        self.SessionLocal = sessionmaker(engine)

    def __enter__(self):
        """Инициализация контекста"""

        self.session = self.SessionLocal()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Финализация контекста"""

        if self.session:
            if exc_type is not None:
                self.session.rollback()
            self.session.close()

    def create_db_and_tables(self) -> None:
        Base.metadata.create_all(self.engine)


    def get_all_scan_configs(self) -> list[ScanConfigGetDTO]:
        """Метод получения всех конфигураций сканирования"""

        statement = select(ScanConfigORM)
        scan_confs_data = self.session.scalars(statement).all()

        result_confs_dto = [ScanConfigGetDTO.model_validate(row, from_attributes=True) for row in scan_confs_data]
        return result_confs_dto


    def get_all_project_configs(self, config_id) -> list[ProjectConfigGetDTO]:
        """
        Метод получения проектов для конфигурации сканирования

        :param config_id: Идентификатор конфига сканирования
        :return: Список настроек проектов
        """

        statement = select(ProjectConfigORM).where(ProjectConfigORM.scan_config_id == config_id)
        project_conf_data = self.session.scalars(statement).all()
        result_confs_dto = [ProjectConfigGetDTO.model_validate(row, from_attributes=True) for row in project_conf_data]
        return result_confs_dto


    def get_project_config(self, config_id: int) -> ProjectConfigGetDTO | None:
        """
        Метод получения всех конфигураций сканирования

        :param config_id: Имя конфигурации сканирования
        :return: Модель сканирования из БД
        """

        statement = select(ProjectConfigORM).where(ProjectConfigORM.id == config_id)
        project_conf_data = self.session.scalars(statement).one()
        result_data_model = ProjectConfigGetDTO.model_validate(project_conf_data, from_attributes=True)
        return result_data_model


    def get_scan_config(self, config_id: int) -> ScanConfigGetDTO | None:
        """
        Метод получения всех конфигураций сканирования

        :param config_id: Имя конфигурации сканирования
        :return: Модель сканирования из БД
        """

        statement = select(ScanConfigORM).where(ScanConfigORM.id == config_id)
        scan_conf_data = self.session.scalars(statement).one()

        scan_conf_data_model = ScanConfigGetDTO.model_validate(scan_conf_data, from_attributes=True)
        return scan_conf_data_model

    def get_all_reports(self) -> list[ReportGetDTO]:

        statement = select(ReportORM)
        reports_data = self.session.scalars(statement).all()
        result_confs_dto = [ReportGetDTO.model_validate(row, from_attributes=True) for row in reports_data]
        return result_confs_dto

    def save_report(self, report_data: ReportAddDTO) -> None:
        report_model = ReportORM(scan_config_id=report_data.scan_config_id)
        self.session.add(report_model)
        self.session.commit()

        addition_rows = []
        for affected_project in report_data.projects:
            addition_rows.append(
                ReportProjectORM(
                    project_config_id=affected_project.project_id,
                    report_id=report_model.id,
                )
            )
            for affected_id in affected_project.affected:
                addition_rows.append(
                    AffectedProjectsORM(
                        project_config_id=affected_project.project_id,
                        affected_id=affected_id,
                    )
                )

        self.session.add_all(addition_rows)
        self.session.commit()

    def get_report(self, report_id: int) -> ReportFullDTO | None:
        statement = select(ReportORM).where(ReportORM.id == report_id)
        report_data = self.session.scalars(statement).one()
        result_base_report_dto = ReportGetDTO.model_validate(report_data, from_attributes=True)

        statement = select(ScanConfigORM).where(ScanConfigORM.id == result_base_report_dto.scan_config_id)
        scan_config_data = self.session.scalars(statement).one()
        print(f'{scan_config_data=}')

        scan_config_dto = ScanConfigGetDTO.model_validate(scan_config_data, from_attributes=True)

        print(f'{scan_config_dto=}')

        statement = (
            select(ReportProjectORM)
            .where(ReportProjectORM.report_id == result_base_report_dto.id)
        )
        reports_projects_data = self.session.scalars(statement).all()

        print(f'{reports_projects_data=}')

        projects_ids = [
            ReportProjectDTO.model_validate(row, from_attributes=True)
            for row in reports_projects_data
        ]

        print(f'{projects_ids=}')

        affects_projects = []
        for project in projects_ids:
            project_id = project.project_config_id
            statement = (
                select(AffectedProjectsORM)
                .where(AffectedProjectsORM.project_config_id == project_id)
            )

            project_data = self.get_project_config(project_id)

            affected_projects_data = self.session.scalars(statement).all()
            print(f'{affected_projects_data=}')
            affected_projects = [
                AffectedProjectDTO.model_validate(row, from_attributes=True)
                for row in affected_projects_data
            ]

            statement = (
                select(AffectedORM).filter(AffectedORM.id.in_([affect.affected_id for affect in affected_projects]))
                .options(joinedload(AffectedORM.vulner))
            )
            query_res = self.session.execute(statement)
            result_affects = query_res.unique().scalars().all()

            affects_projects.append(
                ReportProjectAffectsDTO(
                    project=project_data,
                    affects=[
                        ReportAffectDTO(
                            affected=AffectedGetDTO.model_validate(affect, from_attributes=True),
                            vulner=VulnerGetDTO.model_validate(affect.vulner, from_attributes=True),
                        )
                        for affect in result_affects
                    ]
                )
            )

        report = ReportFullDTO(
            id=result_base_report_dto.id,
            created_at=result_base_report_dto.created_at,
            scan_config_id=result_base_report_dto.scan_config_id,
            scan_config=scan_config_dto,
            affects_projects=affects_projects,

        )

        print(f'{report=}')
        return report

    def get_vulner_data(self, vulner_id: str) -> VulnerGetDTO:
        statement = select(VulnerORM).where(VulnerORM.global_identifier == vulner_id)
        vulner_data = self.session.scalars(statement).one()
        vulner_dto = VulnerGetDTO.model_validate(vulner_data, from_attributes=True)
        return vulner_dto


    def get_vulners(self, page: int = 1, page_size = 20) -> list[VulnerBasicGetDTO]:
        statement = select(VulnerORM).limit(page_size).offset(page * page_size)
        # query = statement
        vulners_data = self.session.scalars(statement).all()

        vulners_dto = []
        for row in vulners_data:
            validated_vulner = VulnerGetDTO.model_validate(row, from_attributes=True)
            score = None
            severity = None
            if ratings := validated_vulner.ratings:
                score = ratings[0].score
                severity = ratings[0].severity

            prepared_model = VulnerBasicGetDTO(
                global_identifier=validated_vulner.global_identifier,
                identifier=validated_vulner.identifier,
                source_name=validated_vulner.source_name,
                source_url=validated_vulner.source_url,
                score=score,
                severity=severity,
            )
            vulners_dto.append(prepared_model)

        return vulners_dto


def main():

    connection_string = 'postgresql+psycopg2://postgres:postgres@localhost:5432/dpss_service_db'
    engine = get_db_engine(connection_string)
    with ServiceDB(engine) as service_db:
        service_db.create_db_and_tables()
        service_db.session.commit()
        # service_db.session.add(
        #     ProjectConfigORM(
        #         name='huhuh',
        #         type='python',
        #         dir_path='kdnkjnskj',
        #         description=',fkfk,fkfk',
        #         scan_config_id=2,
        #     )
        # )
        # new_conf = ScanConfigORM(
        #     name='new',
        #     host='kek',
        #     user='kek',
        #     secret='kek',
        #     description='kek',
        #     port='22',
        #     report_type='kek',
        # )
        # service_db.session.add(new_conf)
        # service_db.session.commit()
        # some_model = ScanConfigAddDTO.model_validate(new_conf, from_attributes=True)
        # print(some_model)

        # service_db.save_report(
        #     ReportAddDTO(
        #         scan_config_id=2,
        #         projects=[
        #             AffectedProjectDTO(
        #                 project_id=2,
        #                 affected=[1,2,3,4],
        #             )
        #         ]
        #     )
        # )

        service_db.get_report(4)


if __name__ == '__main__':
    main()
