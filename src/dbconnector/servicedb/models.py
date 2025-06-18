from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


TIMESTAMP_FORMAT = '%d_%m_%Y_%H_%M_%S'

class Base(DeclarativeBase):
    pass

class ReportORM(Base):
    __tablename__ = 'reports'

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[str] = mapped_column(String(), default=datetime.now().strftime(TIMESTAMP_FORMAT))

    scan_config_id: Mapped[int] = mapped_column(ForeignKey('scan_configs.id', ondelete='SET NULL'))
    # scan_config: Mapped['ScanConfigORM'] = relationship()

    # vulners: Mapped[list['VulnerORM']] = relationship()
    def __repr__(self):
        return f'ReportORM: {self.id=}, {self.created_at=}, {self.scan_config_id=}'


class ProjectConfigORM(Base):
    __tablename__ = 'project_configs'

    # project_config_name: Mapped[str] = mapped_column()
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String())
    type: Mapped[str] = mapped_column(String())
    dir_path: Mapped[str] = mapped_column(String())
    description: Mapped[str | None] = mapped_column(String())
    scan_config_id: Mapped[int] = mapped_column(ForeignKey('scan_configs.id', ondelete='CASCADE'))

    scan_config: Mapped['ScanConfigORM'] = relationship()

    def __repr__(self):
        return f'ProjectConfigORM: {self.id=}, {self.name}, {self.type}, {self.description}'


class ScanConfigORM(Base):
    __tablename__ = 'scan_configs'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String())
    host: Mapped[str] = mapped_column(String())
    user: Mapped[str] = mapped_column(String())
    secret: Mapped[str] = mapped_column(String())
    description: Mapped[str | None] = mapped_column(String())
    date: Mapped[str] = mapped_column(String(), default=datetime.now().strftime(TIMESTAMP_FORMAT))
    port: Mapped[str | None] = mapped_column(String())

    # reports: Mapped[list['ReportORM']] = relationship()
    projects: Mapped[list['ProjectConfigORM']] = relationship()
    # report_type: Mapped[str] = mapped_column(String())

    def __repr__(self):
        return f'ScanConfigORM: {self.id=}, {self.name}, {self.description}, {self.date}'



class AffectedProjectsORM(Base):
    __tablename__ = 'affected_projects'
    id: Mapped[int] = mapped_column(primary_key=True)

    project_config_id: Mapped[str | None] = mapped_column(ForeignKey('project_configs.id'))
    affected_id: Mapped[str | None] = mapped_column(ForeignKey('affects.id'))

    def __repr__(self):
        return f'AffectedProjectsORM: {self.id=}, {self.project_config_id=}, {self.affected_id=}'


# class ReportVulnerORM(Base):
#     __tablename__ = 'reports_vulners'
#
#     id: Mapped[int] = mapped_column(primary_key=True)
#     vulner_id: Mapped[str | None] = mapped_column(ForeignKey('vulners.global_identifier'))
#     report_id: Mapped[int] = mapped_column(ForeignKey('reports.id'))

class ReportProjectORM(Base):
    __tablename__ = 'reports_projects'

    id: Mapped[int] = mapped_column(primary_key=True)
    project_config_id: Mapped[str | None] = mapped_column(ForeignKey('project_configs.id'))
    report_id: Mapped[int | None] = mapped_column(ForeignKey('reports.id'))

    def __repr__(self):
        return f'ReportProjectORM: {self.id=}, {self.project_config_id=}, {self.report_id=}'


class VulnerORM(Base):
    __tablename__ = 'vulners'

    # id: Mapped[int] = mapped_column(primary_key=True)
    global_identifier: Mapped[str] = mapped_column(primary_key=True)
    identifier: Mapped[str]
    description: Mapped[str]
    source_name: Mapped[str]
    source_url: Mapped[str]

    affected: Mapped[list['AffectedORM']] = relationship()
    ratings: Mapped[list['RatingORM']] = relationship()
    references: Mapped[list['ReferenceORM']] = relationship()

    # reports: Mapped[list['ReportORM']] = relationship()
    def __repr__(self):
        return f'VulnerORM: {self.global_identifier=}, {self.identifier=}, {self.source_name=}'


class RatingORM(Base):
    __tablename__ = 'ratings'

    id: Mapped[int] = mapped_column(primary_key=True)
    method: Mapped[str]
    score: Mapped[float]
    severity: Mapped[str]
    source_name: Mapped[str]
    source_url: Mapped[str]
    vector: Mapped[str]
    version: Mapped[float]

    vulner_id: Mapped[str] = mapped_column(ForeignKey('vulners.global_identifier', ondelete='CASCADE'))

    vulner: Mapped['VulnerORM'] = relationship()

    def __repr__(self):
        return f'RatingORM: {self.id=}, {self.method=}, {self.version=}, {self.vector=}, {self.score=}, {self.severity=}'


class ReferenceORM(Base):
    __tablename__ = 'references'

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str]
    url: Mapped[str]

    vulner_id: Mapped[str] = mapped_column(ForeignKey('vulners.global_identifier', ondelete='CASCADE'))

    vulner: Mapped['VulnerORM'] = relationship()

    def __repr__(self):
        return f'RatingORM: {self.id=}, {self.source=}, {self.url=}'


class AffectedORM(Base):
    __tablename__ = 'affects'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    vendor: Mapped[str]
    type: Mapped[str]

    start_condition: Mapped[str]
    start_value: Mapped[str]
    end_value: Mapped[str]
    end_condition: Mapped[str]

    vulner_id: Mapped[str] = mapped_column(ForeignKey('vulners.global_identifier', ondelete='CASCADE'))

    vulner: Mapped['VulnerORM'] = relationship()

    def __repr__(self):
        return f'''
            RatingORM:
            {self.id=},
            {self.name=},
            {self.vendor=},
            {self.type=},
            {self.start_condition=},
            {self.start_value=},
            {self.end_value=},
            {self.end_condition=}
            {self.vulner_id=}
        '''


