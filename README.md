# Flask URL Shortener

This Flask URL Shortener is a simple web application that allows users to create shortened URLs, update them, list all URLs, and delete them either individually or all at once. It uses a base62 encoding scheme to generate the short URLs.

## Getting Started

### Prerequisites

To run this application, you will need:

- Python 3.6 or later
- Flask

You can install Flask using pip:

```bash
pip install Flask
```
### Start
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
