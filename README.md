# Jenkins on Raspberry Pi (Portainer Stack)

Compose stack for Jenkins with JCasC and GitHub Organization Folder discovery.

Published image: `melamchk/jenkins-on-pi:latest` (Docker Hub).

## Required environment

Set the `<pi-host>` placeholder in `casc/jenkins.yaml` (organization defaults to `QuickLifeSolutions`), then provide the following variables (via Portainer, `.env`, or your orchestrator):

- `ADMIN_PASSWORD` — initial Jenkins admin password.
- `GITHUB_TOKEN` — PAT with `repo` + `admin:repo_hook`, used for the shared library and automated pushes (username defaults to `x-access-token`).
- `JENKINS_URL` — externally reachable base URL for the controller (e.g. `https://jenkins.example.com/`).
- `APIFY_TOKEN_DEV` / `APIFY_TOKEN_PROD` — deployment credentials consumed by the shared library.
- `DOCKER_GID` — host Docker group id (e.g. `$(getent group docker | cut -d: -f3)`) so the non-root `jenkins` user can access `/var/run/docker.sock`.
- `AWS_EC2_AGENT_PRIVATE_KEY_FILE` — path inside the container pointing to the PEM file for the EC2 SSH agent (the compose file mounts `/opt/jenkins/secrets/jenkins_agent` to `/run/secrets/aws_ec2_agent_key`).

The EC2 agent key should reside on the Docker host at `/opt/jenkins/secrets/jenkins_agent` (mode `600`). The compose file bind-mounts this file into the container and the CasC bundle references it via `directEntryFromFile`.

Redeploying the stack will reconcile any manual Portainer edits with these declarative settings.
