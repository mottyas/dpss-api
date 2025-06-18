from pydantic import BaseModel

class ProjectConfigAddDTO(BaseModel):
    name: str | None
    type: str | None
    dir_path: str | None
    description: str | None = None
    scan_config_id: int

class ProjectConfigGetDTO(ProjectConfigAddDTO):
    id: int

class ScanConfigAddDTO(BaseModel):
    name: str
    host: str
    user: str
    secret: str
    description: str | None = None
    date: str | None = None
    port: str | None = None
    # report_type: str

class ScanConfigGetDTO(ScanConfigAddDTO):
    id: int
    projects: list['ProjectConfigGetDTO']
    # reports: list['ReportGetDTO']

class AffectedDTO(BaseModel):
    name: str
    vendor: str
    type: str

    start_condition: str
    start_value: str
    end_value: str
    end_condition: str


class AffectedGetDTO(AffectedDTO):
    id: int

# class AffectedIdDTO(BaseModel):
#     affected_id: int

class AffectedProjectDTO(BaseModel):
    affected_id: int
    project_config_id: int

class RatingGetDTO(BaseModel):
    id: int
    method: str
    score: float
    severity: str
    source_name: str
    source_url: str
    vector: str
    version: float

class ReferenceGetDTO(BaseModel):
    id: int
    source: str
    url: str

class VulnerGetDTO(BaseModel):
    global_identifier: str
    identifier: str | None
    description: str | None
    source_name: str | None
    source_url: str | None = None

    affected: list['AffectedGetDTO'] | None = None
    ratings: list['RatingGetDTO'] | None = None
    references: list['ReferenceGetDTO'] | None = None

class VulnerBasicGetDTO(BaseModel):
    global_identifier: str
    identifier: str | None
    source_name: str | None
    source_url: str | None = None
    score: float | None = None
    severity: str | None = None

class VulnersBasicsGetDTO(BaseModel):
    vulners: list['VulnerBasicGetDTO']
    count: int

class ReportProjectDTO(BaseModel):
    id: int
    project_config_id: int
    report_id: int

class AffectedVulnerDTO(AffectedDTO):
    vulners: list[str]

class ProjectVulnersGetDTO(BaseModel):
    project_id: int
    affected: list['AffectedVulnerDTO']

class ReportAddDTO(BaseModel):
    scan_config_id: int
    projects: list['AffectedProjectDTO'] | None

class ReportGetDTO(BaseModel):
    id: int
    created_at: str | None
    scan_config_id: int
    # scan_config: 'ScanConfigGetDTO'

class ReportAffectDTO(BaseModel):
    affected: 'AffectedGetDTO'
    vulner: 'VulnerGetDTO'

class ReportProjectAffectsDTO(BaseModel):
    project: ProjectConfigGetDTO
    affects: list['ReportAffectDTO']

class ReportFullDTO(ReportGetDTO):
    affects_projects: list[ReportProjectAffectsDTO]
    scan_config: 'ScanConfigGetDTO'

class AddItemResponseDTO(BaseModel):
    created_item_id: int
