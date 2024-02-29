## Starting the Services of Assignment 3.1

### Prerequisites

Docker installed on your system

Docker Compose installed on your system

Ensure you have the all of working source files in your project directory.

### Steps to Launch the Services
Navigate to the directory containing your docker-compose.yml file and run the following command:
```bash
docker-compose up --build
```
In our setup, services are configured to run on specific ports, both internally within the Docker network and externally on the host machine. Here is an overview of the port configurations for each service:

The NGINX service acts as a reverse proxy, listening on port 80. It is the entry point for all incoming traffic, routing requests to the appropriate backend service based on the request path.

The Main service is accessible directly at http://localhost:8000 from the host machine. However, for consistency and security, it's recommended to access it through the NGINX proxy.

Similarly, the Auth service can be accessed directly at http://localhost:8001 from the host machine. Like the Main service, it's advisable to access the Auth service through the NGINX proxy for uniformity and security.

## Starting the Services of Assignment 3.2

auth-deployment.yaml, url-deployment.yaml, pv.yaml, pvc.yaml are for deploying our services onto the Kubernetes cluster.

Apply all the four yaml files on the control node with the command:

    $ kubectl apply -f xx.yaml