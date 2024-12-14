# ENV file

```.env```
```.env
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
```

# Docker build

```Build Command.```
```
$ docker build -t go-auth-service:v1 .
```

# Manage Container Service

```Create & Run container using Docker Compose.```
```
$ docker compose up -d
```

```Stop & Delete container using Docker Compose.```
```
$ docker compose down
```