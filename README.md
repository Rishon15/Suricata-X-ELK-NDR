# Title - Suricata X ELK NDR

Implementation of Network Detection and Response lab built using Suricata and ELK stack. Engineered with optimized Elasticsearch routing and selective network traffic filtering. Tested against simulated scenarios using [AlphaSOC Flightsim](https://github.com/alphasoc/flightsim). 

## Objective

The goal of this project was to engineer a raw Network Detection and Response (NDR) pipeline from scratch. Moving beyond pre-packaged SIEM automated installers, this lab was built to provide a deep understanding of network traffic parsing, log routing, and IDS engine tuning.

## Tech Stack

-  **Network Sensor:** Suricata (Configured as IDS/NSM)
-  **Log Shipper:** Filebeat
-  **SIEM / Analytics:** ELK Stack (Elasticsearch, Kibana) deployed via Docker
-  **Adversary Simulation:** AlphaSOC Flightsim

## Setup guide

### 1. Setting up ELK stack

ELK implementation will be done via docker, as its easy to tear-down and redeploy incase a misconfiguration occurs breaking the installation.

1. Install [docker](https://docs.docker.com/get-started/get-docker/) according to your OS, in this case I followed steps from this [webpage](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository).
    Verify docker service by running command `sudo systemctl status docker`
    ![DOcker Service Image](../Pictures/Docker%20service.png)
    Verify if Docker runs using `sudo docker run hello-world`

2. Now we move onto ELK installation, via [logz.io](https://logz.io/blog/elk-stack-on-docker/). Follow the instructions on the website for the installation, instructions are responsible for only creating the container, for its setup we run `docker-compose up setup -d` completing the installation and configuration.
3. To verify if elastic works, open the browser and type `http://localhost:5601`
   ![Elastic login page](../Pictures/Elastic%20dashboard.png)
4. Credentials are `elastic` and password is `changeme` to log into elastic. The dashboard will be empty because there is no agent collecting the data or shipping events, So nexy is installation of `filebeat`.

### 2. Filebeat


    
