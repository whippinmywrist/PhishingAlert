# PhisingAlert

PhisingAlert is a solution for finding phishing sites that use social engineering against your users or take away user traffic for advertising

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

## Testing
```bash
py.test --cov-report term-missing --cov app tests
```
