## Starting the Services of Assignment 3.1

### Prerequisites

Docker installed on your system
Docker Compose installed on your system

### Configuration Files
To start the authentication service, run:
```bash
python3 auth.py
```
The authentication service will start running on http://127.0.0.1:8001

Then open a new terminal and run the below command to start the URL shortener service:
```bash
python3 main.py
```
The URL shortener service will start running on http://127.0.0.1:8000
