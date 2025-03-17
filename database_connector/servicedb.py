import sqlite3
from pathlib import Path

from depss.models import ScanConfigSchema, ProjectConfigSchema

class ServiceDB:
    """Класс работы с базой данных сервера"""

    CREATE_TABLE_SCAN_CONFIGS = '''
    CREATE TABLE IF NOT EXISTS scan_configs (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        host TEXT NOT NULL,
        user TEXT NOT NULL,
        secret TEXT NOT NULL,
        description TEXT NOT NULL,
        date TEXT NOT NULL,
        port TEXT NOT NULL
    );
    '''

    CREATE_TABLE_PROJECT_CONFIGS = '''
    CREATE TABLE IF NOT EXISTS project_configs (
        id INTEGER PRIMARY KEY,
        scan_config_name TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        dir_path TEXT NOT NULL,
        description TEXT NOT NULL
    );
    '''

    SELECT_ALL_SCAN_CONFIGS = '''
    SELECT id, name, host, user, secret, description, date, port
    FROM scan_configs
    '''

    SELECT_SCAN_CONFIGS = '''
    SELECT id, name, host, user, secret, description, date, port
    FROM scan_configs
    WHERE name='{name}'
    '''

    SELECT_PROJECT_CONFIGS = '''
    SELECT id, scan_config_name, name, type, dir_path, description
    FROM project_configs
    WHERE scan_config_name='{scan_config_name}'
    '''

    INSERT_INTO_SCAN_CONFIGS = '''
    INSERT INTO scan_configs
    (name, host, user, secret, description, date, port)
    VALUES ("{name}", '{host}', '{user}', '{secret}', '{description}', '{date}', '{port}')
    '''

    INSERT_INTO_PROJECT_CONFIGS = '''
    INSERT INTO project_configs
    (scan_config_name, name, type, dir_path, description)
    VALUES ("{scan_config_name}", '{name}', '{type}', '{dir_path}', '{description}')
    '''

    # CREATE_TABLE_PROJECT_CONFIGS = '''
    # CREATE TABLE IF NOT EXISTS project_configs (
    #     id INTEGER PRIMARY KEY,
    #     scan_config_name TEXT NOT NULL UNIQUE,
    #     name TEXT NOT NULL,
    #     type TEXT NOT NULL,
    #     dir_path TEXT NOT NULL,
    #     description TEXT NOT NULL,
    # );
    # '''

    CREATE_TABLES = (CREATE_TABLE_SCAN_CONFIGS, CREATE_TABLE_PROJECT_CONFIGS)


    def __init__(self, db_path: Path | str) -> None:
        """
        Инициализация класса

        :param db_path: Путь до файла с БД
        """
        if isinstance(db_path, str):
            db_path = Path(db_path)

        self.db_path = db_path

    def __enter__(self):
        """Инициализация контекста"""

        is_db_exist = self.db_path.exists()
        self.connection = sqlite3.connect(self.db_path)
        if not is_db_exist:
            self.create_tables()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Финализация контекста"""

        self.connection.close()

    def create_tables(self):
        """Метод создания таблиц базы данных"""

        cursor = self.connection.cursor()
        for create_table_query in self.CREATE_TABLES:
            cursor.execute(create_table_query)
        self.connection.commit()

    def get_all_scan_configs(self) -> list[ScanConfigSchema]:
        """Метод получения всех конфигураций сканирования"""

        result_configs = []
        cursor = self.connection.cursor()
        cursor.execute(self.SELECT_ALL_SCAN_CONFIGS)

        scan_configs = cursor.fetchall()
        for scan_config in scan_configs:
            scan_config_id, name, host, user, secret, description, date, port = scan_config
            projects_configs = cursor.execute(self.SELECT_PROJECT_CONFIGS.format(scan_config_name=name))

            scan_configs_projects = []
            for project_config in projects_configs:
                project_config_id, scan_config_name, _name, _type, dir_path, description = project_config
                scan_configs_projects.append(
                    ProjectConfigSchema(
                        name=_name,
                        type=_type,
                        dir_path=dir_path,
                        description=description,
                    )
                )

            result_configs.append(
                ScanConfigSchema(
                    host=host,
                    user=user,
                    secret=secret,
                    date=date,
                    name=name,
                    description=description,
                    port=port,
                    projects=scan_configs_projects,
                )
            )

        return result_configs

    def get_scan_config(self, config_name: str) -> ScanConfigSchema | None:
        """
        Метод получения всех конфигураций сканирования

        :param config_name: Имя конфигурации сканирования
        :return: Модель сканирования из БД
        """

        cursor = self.connection.cursor()
        cursor.execute(self.SELECT_SCAN_CONFIGS.format(name=config_name))

        scan_config = cursor.fetchone()
        if not scan_config:
            return None

        scan_config_id, name, host, user, secret, description, date, port = scan_config
        projects_configs = cursor.execute(self.SELECT_PROJECT_CONFIGS.format(scan_config_name=name))

        scan_configs_projects = []
        for project_config in projects_configs:
            project_config_id, scan_config_name, _name, _type, dir_path, description = project_config
            scan_configs_projects.append(
                ProjectConfigSchema(
                    name=_name,
                    type=_type,
                    dir_path=dir_path,
                    description=description,
                )
            )

        return ScanConfigSchema(
            host=host,
            user=user,
            secret=secret,
            date=date,
            name=name,
            description=description,
            port=port,
            projects=scan_configs_projects,
        )

    def add_scan_config(self, scan_config: ScanConfigSchema) -> None:
        """
        Метод добавления конфигурации сканирования в БД

        :param scan_config: Модель данных конфигурации сканирования
        :return: None
        """

        cursor = self.connection.cursor()
        cursor.execute(
            self.INSERT_INTO_SCAN_CONFIGS.format(
                name=scan_config.name,
                host=scan_config.host,
                user=scan_config.user,
                secret=scan_config.secret,
                description=scan_config.description,
                date=scan_config.date,
                port=scan_config.port,
            )
        )

        for project_config in scan_config.projects:
            cursor.execute(
                self.INSERT_INTO_PROJECT_CONFIGS.format(
                    scan_config_name=scan_config.name,
                    name=project_config.name,
                    type=project_config.type,
                    dir_path=project_config.dir_path,
                    description=project_config.description,
                )
            )

        self.connection.commit()
