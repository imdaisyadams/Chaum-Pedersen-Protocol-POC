# Chaum-Pedersen Protocol Implementation

This project implements the Chaum-Pedersen zero-knowledge proof protocol using Rust and gRPC. 

## Table of Contents

1. [Protocol Overview](#protocol-overview)
2. [Running the Application](#running-the-application)
3. [Docker Usage](#docker-usage)


## Protocol Overview

The Chaum-Pedersen protocol is a zero-knowledge proof system that allows a prover to demonstrate knowledge of a discrete logarithm without revealing the actual value. This demo includes:

- A server that generates challenges and verifies proofs
- A client that can register, login, and provide proofs
- gRPC communication between the client and server
- Docker containerization for both components


## Running the Application

### Without Docker

1. Start the server:
   ```
   cargo run --bin zkp_auth_server
   ```

2. In another terminal, run the client:
   ```
   cargo run --bin zkp_auth_client
   ```

### With Docker

Use Docker Compose to build and run both the server and client:

```
docker compose up --build
```

## Docker Usage

- Build the Docker images:
  ```
  docker-compose build
  ```

- Run the containers:
  ```
  docker compose up
  ```

- Stop the containers:
  ```
  docker compose down
  ```
