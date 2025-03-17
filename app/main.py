from typing import Union
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from depss.models import ProjectConfigSchema, ScanConfigSchema

from database_connector.servicedb import ServiceDB
# from database_connector import


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


