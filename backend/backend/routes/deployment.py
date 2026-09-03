from typing import List
from fastapi import APIRouter, Depends, Request

from backend.schemas.deployment import DeploymentRequest, DeploymentResult
from backend.services.deployment_service import deploy_to_multiple
from backend.services.auth_service import get_current_user
from backend.models.user import User

router = APIRouter(prefix="/deployment", tags=["Deployment"])

@router.post("/push", response_model=List[DeploymentResult])
async def push_deploy(
    request: Request,
    deploy_req: DeploymentRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Deploys the endpoint agent to the specified IP addresses.
    Requires admin privileges.
    """
    # Build the backend API URL dynamically based on the server's host/port, or use env var.
    # We will use the request's base URL as a fallback.
    backend_url = str(request.base_url)
    
    results = await deploy_to_multiple(deploy_req, backend_url)
    return results
