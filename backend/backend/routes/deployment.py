"""Remote agent deployment.

SECURITY NOTE — this route was the single most dangerous gap in the API and is worth stating
plainly, because the code read as authenticated while it was not. It depended on
``get_current_user``, whose documented contract is that it returns ``None`` when no credentials
are supplied, and then never inspected the result. The docstring said "Requires admin privileges".
Anonymous callers could therefore drive a PowerShell remote-install run against a list of IP
addresses of their choosing, supplying their own Windows administrator credentials, from an
unauthenticated HTTP request. That is arbitrary remote code execution on the caller's chosen hosts
using this server as the launcher.

It is now ``require_admin``. ``get_current_user`` is not imported here at all, so the mistake
cannot be made again by editing this file.
"""

from typing import List

from fastapi import APIRouter, Depends, Request

from backend.app.dependencies import require_admin
from backend.models.user import User
from backend.schemas.deployment import DeploymentRequest, DeploymentResult
from backend.services.deployment_service import deploy_to_multiple

router = APIRouter(prefix="/deployment", tags=["Deployment"])


@router.post("/push", response_model=List[DeploymentResult])
async def push_deploy(
    request: Request,
    deploy_req: DeploymentRequest,
    current_user: User = Depends(require_admin),
):
    """Deploy the endpoint agent to the specified IP addresses. Administrators only.

    The Windows credentials in ``deploy_req`` are the CALLER'S, used for the remote install, and
    are not stored. They are still passed to PowerShell as command-line arguments by
    ``deployment_service.deploy_to_multiple``, which exposes them in the process table of this
    host for the lifetime of each child process - see the note there. That is a separate,
    documented residual risk; authenticating the route bounds who can trigger it but does not
    remove it.
    """
    # Build the backend API URL dynamically based on the server's host/port, or use env var.
    # We will use the request's base URL as a fallback.
    backend_url = str(request.base_url)

    results = await deploy_to_multiple(deploy_req, backend_url)
    return results
