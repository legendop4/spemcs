import asyncio
import subprocess
from pathlib import Path
import logging
from typing import List

from backend.schemas.deployment import DeploymentRequest, DeploymentResult

logger = logging.getLogger(__name__)

# Assuming the agent binaries are placed in a known location on the server
# You can customize this path as needed.
AGENT_SOURCE_PATH = Path("agent_binaries/publish").resolve()
DEPLOY_SCRIPT = Path("backend/scripts/remote_deploy.ps1").resolve()

async def deploy_to_ip(ip: str, request: DeploymentRequest, backend_api_url: str) -> DeploymentResult:
    """Deploys the agent to a single IP address."""
    if not AGENT_SOURCE_PATH.exists():
        return DeploymentResult(ip=ip, status="failed", message=f"Agent source path not found at {AGENT_SOURCE_PATH}")
    
    if not DEPLOY_SCRIPT.exists():
        return DeploymentResult(ip=ip, status="failed", message=f"Deployment script not found at {DEPLOY_SCRIPT}")

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", str(DEPLOY_SCRIPT),
        "-TargetIP", ip,
        "-Username", request.admin_username,
        "-Password", request.admin_password,
        "-AgentSourcePath", str(AGENT_SOURCE_PATH),
        "-BackendApiUrl", backend_api_url
    ]

    try:
        # Run subprocess asynchronously
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            return DeploymentResult(ip=ip, status="success", message="Deployment successful.")
        else:
            error_msg = stderr.decode('utf-8', errors='ignore').strip() or stdout.decode('utf-8', errors='ignore').strip()
            return DeploymentResult(ip=ip, status="failed", message=error_msg)
            
    except Exception as e:
        logger.exception(f"Exception during deployment to {ip}")
        return DeploymentResult(ip=ip, status="failed", message=str(e))

async def deploy_to_multiple(request: DeploymentRequest, backend_api_url: str) -> List[DeploymentResult]:
    """Deploys the agent to multiple IPs concurrently."""
    tasks = [deploy_to_ip(ip, request, backend_api_url) for ip in request.ips]
    results = await asyncio.gather(*tasks)
    return results
