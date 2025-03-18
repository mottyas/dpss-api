from typing import Union
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from depss.models import ProjectConfigSchema, ScanConfigSchema, DetectedSoftSchema, DetectedVulnerabilitySchema, ReportModelSchema
from depss.scanner import Scanner
from depss.sbom import GeneratorSBOM, ParserSBOM
from depss.reporter import Reporter
from depss.vulnerdb import VulnerabilityDB
from depss.utils import check_is_vulnerable, orjson_load_file, orjson_dump_file

from database_connector.servicedb import ServiceDB
# from database_connector import

DATA_DIR = Path('/home/motya/malife/projects/depss/data')

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}


@app.post('/scan_config')
def save_config(scan_config: ScanConfigSchema) -> None:
    with ServiceDB(Path('/home/motya/malife/projects/depss-api/databases/service.db')) as service_db:
        service_db.add_scan_config(scan_config)


@app.post('/scan_by_config')
def save_config(scan_config: ScanConfigSchema) -> None:
    with ServiceDB(Path('/home/motya/malife/projects/depss-api/databases/service.db')) as service_db:
        service_db.add_scan_config(scan_config)


@app.post('/scan_by_config_with_report')
def scan_by_config_with_report(scan_config: ScanConfigSchema) -> None:

    # project_config = ProjectConfigSchema(
    #     name='first_proj',
    #     type='python',
    #     dir=PROJECT_DIR,
    #     description='first_proj',
    # )
    #
    # scan_config = ScanConfigSchema(
    #     host=HOST,
    #     user=USER,
    #     secret=PASSWORD,
    #     name='first_scan',
    #     projects=[project_config],
    # )


    scanner = Scanner(scan_config=scan_config)

    scanner.save_project_requirements()
    project_dir = DATA_DIR / scanner.config.projects[0].type / scanner.config.projects[0].name

    import logging

    logging.error(f'project_dir: >{project_dir}<')

    sbom_generator = GeneratorSBOM(
        source_path='./python/etlsrc/',
        output_path='./',
    )

    sbom_generator.generate_sbom(is_need_dump_file=True)

    parser = ParserSBOM(Path('./') / 'sbom.json')

    # logging.error(f'parser: {parser.sbom}')

    # components = []
    for component in parser.sbom.get('components', []):
        if not component.get('purl'):
            logging.error(f'component: {component}')

    components = parser.get_components()

    db_path = Path('/home/motya/malife/projects/depss/vulnerabilities/vulner.db')
    # found_vulnerabilities = []
    # vulner_db = VulnerabilityDB(db_path)
    package_folder = '/home/motya/malife/projects/depss/vulnerabilities/packages/pyup-1.20250224.001/content'
    with VulnerabilityDB(db_path=db_path, package_folder=package_folder) as vulner_db:

        found_vulnerabilities = {}
        for component in components:
            pkg_version = component.version
            pkg_name = component.name

            print(pkg_name, pkg_version)

            vulnerabilities = vulner_db.get_package_vulnerabilities(pkg_name)
            for vulner in vulnerabilities:
                vulnerability, source, pkg_name, vulnerable_interval = vulner
                is_vulnerable = check_is_vulnerable(pkg_version, vulnerable_interval)
                print(vulner)
                print(is_vulnerable)
                if is_vulnerable:
                    if not found_vulnerabilities.get(vulnerability):
                        found_vulnerabilities[vulnerability] = {
                            'id': vulnerability,
                            'source': source,
                            'soft': []
                        }
                    found_vulnerabilities[vulnerability]['soft'].append(
                        DetectedSoftSchema(
                            vulnerable_interval=vulnerable_interval,
                            pkg_name=pkg_name,
                            pkg_version=pkg_version,
                        )
                    )

        detected_vulnerabilities = []
        for vulner, data in found_vulnerabilities.items():
            detected_vulnerabilities.append(
                DetectedVulnerabilitySchema(
                    vulner_id=vulner,
                    source_name=data['source'],
                    affected_soft=data['soft'],
                )
            )

        # vulner_db.connection.close()

        reporter = Reporter(
            detected_vulnerabilities=detected_vulnerabilities
        )

        report = reporter.generate_report()

        from pprint import pprint

        pprint(report)
        import json
        orjson_dump_file(
            output_dir=DATA_DIR,
            filename='kek.json',
            data=json.loads(report.model_dump_json())
        )
        # return report


@app.get("/get_report")
def get_report():
    return orjson_load_file(DATA_DIR / 'kek.json')
