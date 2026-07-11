"""Agent file download endpoint — serves install scripts and agent binaries."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse

router = APIRouter(prefix="/agents", tags=["agents"])

_AGENTS_DIR = Path(__file__).resolve().parents[4] / "agents"

_FILE_MAP = {
    "linux": {
        "install": ("linux/install.sh", "text/x-shellscript"),
        "agent": ("linux/vulnint-agent.py", "text/x-python"),
    },
    "windows": {
        "install": ("windows/Install-Agent.ps1", "text/plain"),
        "agent": ("windows/vulnint-agent.ps1", "text/plain"),
    },
}


def _get_agent_path(os_name: str, file_type: str) -> Path:
    mapping = _FILE_MAP.get(os_name)
    if not mapping:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown OS: {os_name}. Use 'linux' or 'windows'.",
        )
    rel = mapping.get(file_type)
    if not rel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown file type: {file_type}. Use 'install' or 'agent'.",
        )
    return _AGENTS_DIR / rel[0]


@router.get("/{os}/install")
async def get_install_script(os: str):
    """Serve the OS-specific install script (public — no auth needed).

    Linux:  curl -fsS https://vulnint.example.com/api/v1/agents/linux/install | sudo bash
    Windows: Invoke-Expression (Invoke-WebRequest https://vulnint.example.com/api/v1/agents/windows/install).Content
    """
    filepath = _get_agent_path(os, "install")
    mapping = _FILE_MAP[os]["install"]
    content = filepath.read_text()
    return PlainTextResponse(content=content, media_type=mapping[1])


@router.get("/{os}/agent")
async def get_agent_script(os: str):
    """Serve the agent script itself (public — needed for direct download)."""
    filepath = _get_agent_path(os, "agent")
    mapping = _FILE_MAP[os]["agent"]
    content = filepath.read_text()
    return PlainTextResponse(content=content, media_type=mapping[1])


@router.get("/{os}/config-example")
async def get_config_example(os: str):
    """Serve a config example so users know what to configure."""
    config_path = _AGENTS_DIR / os / "config.example.yaml"
    if not config_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return PlainTextResponse(content=config_path.read_text(), media_type="text/yaml")
