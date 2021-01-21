# PhisingAlert

PhisingAlert is a solution for finding phishing sites that use social engineering against your users or take away user traffic for advertising

## How to use it

```bash
# Get the code
git clone https://github.com/whippinmywrist/PhisingAlert.git
cd PhisingAlert
# Virtualenv modules installation (Unix based systems)
virtualenv env
source env/bin/activate
# Install modules
pip3 install -r requirements.txt
# Set the FLASK_APP environment variable (Unix/Mac) 
export FLASK_APP=run.py
# Set up the DEBUG environment (Unix/Mac)
export FLASK_ENV=development
# Start the application (development mode)
# --host=0.0.0.0 - expose the app on all network interfaces (default 127.0.0.1)
# --port=5000    - specify the app port (default 5000)  
flask run --host=0.0.0.0 --port=5000
#Access the dashboard in browser: http://127.0.0.1:5000/
```

## Deployment

The app is provided with a basic configuration to be executed in [Docker](https://www.docker.com/)


### [Docker](https://www.docker.com/) execution
---
The application can be easily executed in a docker container. The steps:

> Get the code
```bash
git clone https://github.com/whippinmywrist/PhisingAlert.git
cd PhisingAlert
```

> Start the app in Docker

```bash
sudo docker-compose pull && sudo docker-compose build && sudo docker-compose up -d
```

Visit `http://localhost:5000` in your browser. The app should be up & running.

