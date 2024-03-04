## Starting the Services of Assignment 3.1

### Prerequisites

Docker installed on your system

Docker Compose installed on your system

Ensure you are in the right directory.

### Steps to Launch the Services
Navigate to the directory named 3.1,  run the following command:
```bash
docker-compose up --build
```
In our setup, services are configured to run on specific ports, both internally within the Docker network and externally on the host machine. Here is an overview of the port configurations for each service:

The NGINX service acts as a reverse proxy, listening on port 80. It is the entry point for all incoming traffic, routing requests to the appropriate backend service based on the request path.

The Main service is accessible directly at http://localhost:8000 from the host machine. However, for consistency and security, it's recommended to access it through the NGINX proxy.

Similarly, the Auth service can be accessed directly at http://localhost:8001 from the host machine. Like the Main service, it's advisable to access the Auth service through the NGINX proxy for uniformity and security.

## Starting the Services of Assignment 3.2

### Prerequisites
Set up the Kubernetes cluster correctly. In this assignment we installed k8s v1.23.

```
$ kubectl get nodes
---
NAME            STATUS   ROLES                  AGE    VERSION
kubeclass-242   Ready    <none>                 4d6h   v1.23.17
kubeclass-243   Ready    <none>                 4d6h   v1.23.17
kubeclass-244   Ready    control-plane,master   4d6h   v1.23.17
```

### Steps to Launch the Services
Navigate to the directory named 3.2, the yaml files (auth-deployment.yaml, url-deployment.yaml, redis-delpyment.yaml, redis-pv.yaml and redis-pvc.yaml) are for deploying our services onto the Kubernetes cluster.

Make sure you have all the yaml files on the control node and run the below command there:

    $ kubectl apply -f xx.yaml

To view the deployments, run:

```
$ kubectl get pods
---
NAME                               READY   STATUS    RESTARTS   AGE
auth-deployment-74b8cb857f-2fxrc   1/1     Running   0          21h
redis-deployment-8d7d5674-dvgff    1/1     Running   0          21h
url-deployment-7fdf6bfb9-ccj2r     1/1     Running   0          21h
url-deployment-7fdf6bfb9-dgkmf     1/1     Running   0          21h
url-deployment-7fdf6bfb9-vwn5k     1/1     Running   0          21h
```

Our deployments are configured to run in the default namespace. The URL-shortener service has 3 replicas running.

To view the services, run:

```
$ kubectl get services
---
NAME            TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE
auth-service    NodePort    10.107.173.103   <none>        8001:31178/TCP   4d6h
kubernetes      ClusterIP   10.96.0.1        <none>        443/TCP          4d6h
redis-service   ClusterIP   10.98.81.93      <none>        6379/TCP         21h
url-service     NodePort    10.99.10.174     <none>        8000:31520/TCP   4d6h
```

The auth-service and url-service are of type NodePort thus we could access them with the node IP address followed by the port number. For example, to access the authentication service we could send requests to  http://145.100.135.244:31520/ (with the control node IP address 145.100.135.244).