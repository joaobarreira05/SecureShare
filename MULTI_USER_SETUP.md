# Multi-User Simulation Guide

This guide explains how to use the multi-container Docker setup to simulate interactions between multiple users in the SecureShare system.

## Prerequisites
- Docker and Docker Compose installed.
- The project repository cloned.

## 1. Start the Environment
Run the following command to build and start the backend, SonarQube, and 3 CLI containers:

```bash
docker-compose up -d --build
```

Check if everything is running:
```bash
docker ps
```
You should see `secureshare`, `sonarqube`, `cli-1`, `cli-2`, and `cli-3`.

## 2. Accessing the CLI Containers
You can use any of the 3 CLI containers (`cli-1`, `cli-2`, `cli-3`) to act as any user. They are identical and pre-configured to connect to the backend.

To open a terminal in a container:

```bash
# Open a shell in cli-1
docker exec -it project-2-secureshare-119792_119876_120054-cli-1-1 /bin/bash

# Open a shell in cli-2
docker exec -it project-2-secureshare-119792_119876_120054-cli-2-1 /bin/bash

# Open a shell in cli-3
docker exec -it project-2-secureshare-119792_119876_120054-cli-3-1 /bin/bash
```
*(Note: If the container name is different, check `docker ps` and adjust accordingly)*

## 3. Managing the Environment

### Restarting the Backend
If you make changes to the backend code (and rebuild is not needed), you can restart just the backend service:
```bash
docker-compose restart secureshare
```

### Rebuilding Containers
If you modify `Dockerfile`, `requirements.txt`, or need to update the code inside the containers (since code is not mounted in this setup):
```bash
docker-compose up -d --build
```
This will rebuild the images and recreate the containers.

### Data Persistence
The database file `secureshare.db` is mounted as a volume in `docker-compose.yml`:
```yaml
    volumes:
      - ./secureshare.db:/app/secureshare.db
```
This means that **even if you stop, restart, or rebuild the containers, the database data (users, logs, etc.) will be preserved** as long as you don't delete the `secureshare.db` file on your host machine.

## 4. Example Usage
Inside any CLI container, you can run commands as usual:

```bash
# Login
secureshare auth login

# List users
secureshare users list

# Create a user
secureshare users create
```

You can use different containers to simulate different users simultaneously (e.g., Admin in `cli-1`, User A in `cli-2`).
