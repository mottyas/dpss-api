import sqlalchemy as db
from sqlalchemy.engine.base import Engine
from configs.settings import SERVICE_DB_CONNECTION_STRING


def get_db_engine(connection_string: str = SERVICE_DB_CONNECTION_STRING) -> Engine:
    """
    Функция получения движка для базы данных

    :param connection_string: Строка подключения к БД
    :return: Движок базы данных
    """

    return db.create_engine(connection_string, echo=False)
