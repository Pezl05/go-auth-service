# Environment

.env file
```Environment
# The hostname or IP address of the database server
DB_HOST=<Database host, e.g., localhost or db.example.com>

# The port number used to connect to the database
DB_PORT=<Database port, e.g., 5432 for PostgreSQL>

# The username required to authenticate with the database
DB_USER=<Database username, e.g., admin or root>

# The password associated with the database user account
DB_PASSWORD=<Database password, keep this secure>

# The name of the specific database to connect to
DB_NAME=<Database name, e.g., app_db or test_db>

# A secret key for signing and verifying JSON Web Tokens (JWT)
JWT_KEY=<Strong and unique key for JWT authentication>

# The password for the admin user account
ADMIN_PASSWORD=<Admin password>

# OpenTelemetry resource attributes
OTEL_RESOURCE_ATTRIBUTES=<Resource attributes, e.g., service.name=auth-service>

# The endpoint for OpenTelemetry data export
OTEL_EXPORTER_OTLP_ENDPOINT=<OpenTelemetry exporter endpoint, e.g., http://localhost:4317>
```

# Run Development

Initialize the database first.

```Docker-compose file
# Docker-compose.yaml
version: '3.8'

services:
  db:
    image: postgres:latest
    container_name: project_mgmt_db
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: P@ssw0rd
      POSTGRES_DB: project_mgmt
    volumes:
      - ./database/data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - project_network
  
volumes:
  postgres_data:

networks:
  project_network:
```

Create & Run Database Container using Docker Compose 
```
$ docker compose up -d
```

Build Command.
```
# Download dependencies
$ go mod tidy

# Go Run Application
$ go run .
```

# Run Container
```
# Docker-compose.yaml file
version: '3.8'

services:
  db:
    image: postgres:latest
    container_name: project_mgmt_db
    environment:
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: P@ssw0rd
      POSTGRES_DB: project_mgmt
    volumes:
      - ./database/data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    networks:
      - project_network
  
  auth-service:
    build: .
    image: go-auth-service:v1
    container_name: auth-service
    environment:
      - DB_HOST=db
      - DB_PORT=5432
      - DB_USER=admin
      - DB_PASSWORD=P@ssw0rd
      - DB_NAME=project_mgmt
      - JWT_KEY=P@ssw0rd
    ports:
      - "3000:3000"
    networks:
      - project_network
    depends_on:
      - db
    restart: unless-stopped

volumes:
  postgres_data:

networks:
  project_network:
```

Create & Run container using Docker Compose.
```
$ docker compose up -d --build
```

Stop & Delete container using Docker Compose.
```
$ docker compose down
```