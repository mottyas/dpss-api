
from pymongo import MongoClient

from sqlalchemy.engine import create_engine
from sqlalchemy.orm import Session, sessionmaker
from configs.settings import SERVICE_DB_CONNECTION_STRING

from dbconnector.servicedb.models import (
    Base,
    VulnerORM,
    AffectedORM,
    RatingORM,
    ReferenceORM,
)


engine = create_engine(
    'postgresql+psycopg2://postgres:postgres@localhost:5432/dpss_service_db',
    echo=True,
)

LocalSession = sessionmaker(engine)


def main():
    # url = 'mongodb://admin:admin@localhost:27017/'
    # mongo_client = MongoClient('mongodb://admin:admin@localhost:27017/')
    # parser_db = mongo_client['parser']
    #
    # collection = parser_db['pyup']
    with LocalSession() as session:
        Base.metadata.create_all(engine)
    #     for doc in collection.find({}):
    #         vulner = VulnerORM(
    #             global_identifier=doc['global_identifier'],
    #             identifier=doc['identifier'],
    #             description=doc['description']['en'],
    #             source_name=doc['source'][0]['source_name'],
    #             source_url=doc['source'][0]['source_url'],
    #         )
    #
    #         session.add(vulner)
    #         session.commit()
    #         all_related_rows = []
    #         for affected in doc['affects']:
    #             all_related_rows.append(
    #                 AffectedORM(
    #                     name=affected['name'],
    #                     vendor=affected['vendor'],
    #                     type=affected['pkg_type'],
    #                     start_condition=affected['version']['start_condition'],
    #                     start_value=affected['version']['start_value'],
    #                     end_value=affected['version']['end_value'],
    #                     end_condition=affected['version']['end_condition'],
    #                     vulner=vulner,
    #                 )
    #             )
    #
    #         for reference in doc['references']:
    #             all_related_rows.append(
    #                 ReferenceORM(
    #                     source=reference['source'],
    #                     url=reference['url'],
    #                     vulner=vulner,
    #                 )
    #             )
    #
    #         for rating in doc['ratings']:
    #             all_related_rows.append(
    #                 RatingORM(
    #                     method=rating['method'],
    #                     score=rating['score'],
    #                     severity=rating['severity'],
    #                     source_name=rating['source_name'],
    #                     source_url=rating['source_url'],
    #                     vector=rating['vector'],
    #                     version=rating['version'],
    #                     vulner=vulner,
    #                 )
    #             )
    #         session.add_all(all_related_rows)
    #         session.commit()


if __name__ == '__main__':
    main()
