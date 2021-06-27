# PhishingAlert

PhishingAlert is a solution for finding phishing sites that use social engineering against your users or take away user traffic for advertising

## Deployment

The app is provided with a basic configuration to be executed in [Docker](https://www.docker.com/)


### [Docker](https://www.docker.com/) execution
---
The application can be easily executed in a docker container. The steps:

> Get the code
```bash
git clone https://github.com/whippinmywrist/PhishingAlert.git
cd PhishingAlert
```

> Start the app in Docker

```bash
docker-compose pull && docker-compose build && docker-compose up -d
```

Visit `http://localhost:5000` in your browser. The app should be up & running.

## Testing
```bash
py.test -s --cov-report term-missing --cov app tests --cov domain_processor 
```
