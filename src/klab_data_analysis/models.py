from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class Product:
    id: int
    vendor: str
    name: str


@dataclass(frozen=True)
class Vulnerability:
    kla_id: str
    description: str
    publish_date: date
    start_vuln_version: str
    fixed_version: str
