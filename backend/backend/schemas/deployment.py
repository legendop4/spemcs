from typing import List, Optional
from pydantic import BaseModel

class DeploymentRequest(BaseModel):
    ips: List[str]
    admin_username: str
    admin_password: str
    lab_name: Optional[str] = None
    building_name: Optional[str] = None

class DeploymentResult(BaseModel):
    ip: str
    status: str  # "pending", "success", "failed"
    message: Optional[str] = None
