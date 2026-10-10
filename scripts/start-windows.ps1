$ErrorActionPreference = "Stop"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker Desktop is required for the one-command setup. Install/start Docker Desktop, then rerun this script."
}
docker compose up --build
