# """
# Модуль работы с сервисной базой данных
# """
#
# import sqlite3
# from pathlib import Path
#
# from dpss.models import ScanConfigSchema, ProjectConfigSchema
#
# from schemas.pydantic.scanner_schemas import UpdateScanConfigSchema
# from dbconnector.sql import *
#
#
# class ServiceDB:
#     """Класс работы с базой данных сервера"""
#
#     CREATE_TABLES = (CREATE_TABLE_SCAN_CONFIGS, CREATE_TABLE_PROJECT_CONFIGS)
#
#     def __init__(self, db_path: Path | str) -> None:
#         """
#         Инициализация класса
#
#         :param db_path: Путь до файла с БД
#         """
#         if isinstance(db_path, str):
#             db_path = Path(db_path)
#
#         self.db_path = db_path
#
#     def __enter__(self):
#         """Инициализация контекста"""
#
#         is_db_exist = self.db_path.exists()
#         self.connection = sqlite3.connect(self.db_path)
#         if not is_db_exist:
#             self.create_tables()
#         return self
#
#     def __exit__(self, exc_type, exc_val, exc_tb):
#         """Финализация контекста"""
#
#         self.connection.close()
#
#     def create_tables(self):
#         """Метод создания таблиц базы данных"""
#
#         cursor = self.connection.cursor()
#         for create_table_query in self.CREATE_TABLES:
#             cursor.execute(create_table_query)
#         self.connection.commit()
#
#     def get_all_scan_configs(self) -> list[ScanConfigSchema]:
#         """Метод получения всех конфигураций сканирования"""
#
#         result_configs = []
#         cursor = self.connection.cursor()
#         cursor.execute(SELECT_ALL_SCAN_CONFIGS)
#
#         scan_configs = cursor.fetchall()
#         for scan_config in scan_configs:
#             scan_config_id, name, host, user, secret, description, date, port, report_type = scan_config
#             projects_configs = cursor.execute(SELECT_PROJECT_CONFIGS.format(scan_config_name=name))
#
#             scan_configs_projects = []
#             for project_config in projects_configs:
#                 project_config_id, scan_config_name, _name, _type, dir_path, description = project_config
#                 scan_configs_projects.append(
#                     ProjectConfigSchema(
#                         name=_name,
#                         type=_type,
#                         dir=dir_path,
#                         description=description,
#                     )
#                 )
#
#             result_configs.append(
#                 ScanConfigSchema(
#                     host=host,
#                     user=user,
#                     secret=secret,
#                     date=date,
#                     name=name,
#                     description=description,
#                     port=port,
#                     report_type=report_type,
#                     projects=scan_configs_projects,
#                 )
#             )
#
#         return result_configs
#
#     def get_scan_config(self, config_name: str, is_id: bool = True) -> ScanConfigSchema | None:
#         """
#         Метод получения всех конфигураций сканирования
#
#         :param config_name: Имя конфигурации сканирования
#         :param is_id: Является поле идентификатором
#         :return: Модель сканирования из БД
#         """
#
#         cursor = self.connection.cursor()
#
#         select_scan_conf_query = SELECT_SCAN_CONFIGS.format(name=config_name)
#         if is_id:
#             select_scan_conf_query = SELECT_SCAN_CONFIG_BY_ID.format(id=config_name)
#
#         cursor.execute(select_scan_conf_query)
#
#         scan_config = cursor.fetchone()
#         if not scan_config:
#             return None
#
#         scan_config_id, name, host, user, secret, description, date, port, report_type = scan_config
#         projects_configs = cursor.execute(SELECT_PROJECT_CONFIGS.format(scan_config_name=name))
#
#         scan_configs_projects = []
#         for project_config in projects_configs:
#             project_config_id, scan_config_name, _name, _type, dir_path, description = project_config
#             scan_configs_projects.append(
#                 ProjectConfigSchema(
#                     name=_name,
#                     type=_type,
#                     dir=dir_path,
#                     description=description,
#                 )
#             )
#
#         return ScanConfigSchema(
#             host=host,
#             user=user,
#             secret=secret,
#             date=date,
#             name=name,
#             description=description,
#             port=port,
#             report_type=report_type,
#             projects=scan_configs_projects,
#         )
#
#
#     def get_all_configs(self) -> list[ScanConfigSchema] | None:
#         """
#         Метод получения всех конфигураций сканирования
#
#         :return: Модель сканирования из БД
#         """
#
#         cursor = self.connection.cursor()
#
#         cursor.execute(SELECT_ALL_SCAN_CONFIGS)
#
#         scan_configs = cursor.fetchall()
#         if not scan_configs:
#             return None
#
#         result = []
#         for scan_config in scan_configs:
#             scan_config_id, name, host, user, secret, description, date, port, report_type = scan_config
#             projects_configs = cursor.execute(SELECT_PROJECT_CONFIGS.format(scan_config_name=name))
#
#             scan_configs_projects = []
#             for project_config in projects_configs:
#                 project_config_id, scan_config_name, _name, _type, dir_path, description = project_config
#                 scan_configs_projects.append(
#                     ProjectConfigSchema(
#                         name=_name,
#                         type=_type,
#                         dir=dir_path,
#                         description=description,
#                     )
#                 )
#
#             result.append(
#                 ScanConfigSchema(
#                     host=host,
#                     user=user,
#                     secret=secret,
#                     date=date,
#                     name=name,
#                     description=description,
#                     port=port,
#                     report_type=report_type,
#                     projects=scan_configs_projects,
#                 )
#             )
#
#         return result
#
#     def delete_scan_config(self, config_name: str | int, is_id: bool = True) -> None:
#         """
#         Метод удаления конфигурации
#
#         :param config_name: Имя конфигурации сканирования
#         :param is_id: Является ли имя конфига идентификатором
#         """
#
#         delete_scan_query = DELETE_SCAN_CONFIG.format(config_name)
#         if is_id:
#             delete_scan_query = DELETE_SCAN_CONFIG_BY_ID.format(config_name)
#
#         cursor = self.connection.cursor()
#         cursor.execute(delete_scan_query)
#         cursor.close()
#         self.connection.commit()
#
#     def update_scan_config(self, config_name: str | int, update_config_schema: UpdateScanConfigSchema, is_id: bool = True) -> UpdateScanConfigSchema:
#         """
#         Метод обновления конфигурации сканирования
#
#         :param config_name: Имя конфигурации сканирования
#         :param update_config_schema: Обновленная конфигурация
#         :param is_id: Является ли имя конфига идентификатором
#         :return: Обновленная схема конфигурации
#         """
#
#         params = dict(
#             name=update_config_schema.name,
#             host=update_config_schema.host,
#             user=update_config_schema.user,
#             secret=update_config_schema.secret,
#             description=update_config_schema.description,
#             date=update_config_schema.date,
#             port=update_config_schema.port,
#             report_type=update_config_schema.report_type,
#         )
#
#         delete_scan_query = UPDATE_SCAN_CONFIG.format(**params)
#         if is_id:
#             params['id'] = config_name
#             delete_scan_query = UPDATE_SCAN_CONFIG_BY_ID.format(**params)
#
#         cursor = self.connection.cursor()
#         cursor.execute(delete_scan_query)
#         cursor.close()
#         self.connection.commit()
#
#         return update_config_schema
#
#     def add_scan_config(self, scan_config: ScanConfigSchema) -> None:
#         """
#         Метод добавления конфигурации сканирования в БД
#
#         :param scan_config: Модель данных конфигурации сканирования
#         :return: None
#         """
#
#         cursor = self.connection.cursor()
#         cursor.execute(
#             INSERT_INTO_SCAN_CONFIGS.format(
#                 name=scan_config.name,
#                 host=scan_config.host,
#                 user=scan_config.user,
#                 secret=scan_config.secret,
#                 description=scan_config.description,
#                 date=scan_config.date,
#                 port=scan_config.port,
#                 report_type=scan_config.report_type,
#             )
#         )
#
#         for project_config in scan_config.projects:
#             cursor.execute(
#                 INSERT_INTO_PROJECT_CONFIGS.format(
#                     scan_config_name=scan_config.name,
#                     name=project_config.name,
#                     type=project_config.type,
#                     dir_path=project_config.dir,
#                     description=project_config.description,
#                 )
#             )
#
#         self.connection.commit()
