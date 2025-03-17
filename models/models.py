from pydantic import BaseModel


class ScanConfig(BaseModel):
    host: str
    user: str
    secret: str
    name: str
    port: int
