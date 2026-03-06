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
    ![Docker Service Image](/Pictures/Docker%20service.png)
    Verify if Docker runs using `sudo docker run hello-world`

2. Now we move onto ELK installation, via [logz.io](https://logz.io/blog/elk-stack-on-docker/). Follow the instructions on the website for the installation, instructions are responsible for only creating the container, for its setup we run `docker-compose up setup -d` completing the installation and configuration.
3. To verify if elastic works, open the browser and type `http://localhost:5601`
   ![Elastic login page](/Pictures/Elastic%20dashboard.png)
4. Credentials are `elastic` and password is `changeme` to log into elastic. The dashboard will be empty because there is no agent collecting the data or shipping events, So next is installation of `suricata` which logs network events.

### 2. [Suricata](https://docs.suricata.io/en/suricata-8.0.3/install/ubuntu.html)

High-performance, open-source network analysis and threat detection engine that functions as an Intrusion Detection System (IDS), Intrusion Prevention System (IPS), and Network Security Monitoring (NSM) tool.
    
1. Suricata can be downloaded by visiting [suricata.io](https://docs.suricata.io/en/suricata-8.0.3/install/ubuntu.html) and follow instructions. After completing the installation go to the [after installation](https://docs.suricata.io/en/suricata-8.0.3/quickstart.html#basic-setup) and follow instructions and configure it according to your device.
2. Configure the `$Home_NET` field and add your device's IP subnet and then head to the `af-packet` section. There add the network device interface, save the file and run `suricata-update` so it can fetch the rules file and create `eve.json` file.
3. For this project as we are creating and testing rules we will create a `local.rules` file and add it to `/etc/suricata/rules/local.rules`. The directory path of `local.rules` is also added to `rule-file` section in `suricata.yaml` file so suricata knows to load our custom rules as well. Next install `filebeat` that can ship the generated logs to `elasticsearch` or `logstash`.

### 3. Filebeat

Lightweight, open-source log data shipper used to centralize log files from servers to Elasticsearch or Logstash for analysis.

Run the following commands
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update
sudo apt-get install filebeat
```

1. Starting with its config file `/etc/filebeat/filebeat.yml`, scroll down to `Outputs` section and make the following changes, we uncoment `username` and `password` fields to look like this.
   ![Filebeat Outputs section](/Pictures/Filebeat%20Output.png)
    Next we enable the suricata in filebeat using the command `sudo filebeat modules enable suricata`. With the module enabled we go to its config file in `/etc/filebeat/modules.d/suricata.yml`, set `enabled: true` and `var.paths: ["/var/log/suricata/eve.json"]`.
   ![Filebeat Suricata module image](/Pictures/Filebeat%20Suricata-Module.png)
2. Run the command `sudo systemctl enable filebeat` and `sudo systemctl start filebeat` to start filebeat as a service everytime the machine boots up. Restsrat the container using `docker-compose down` and then `docker-compose up -d` in the cloned directory. 

### 4. [Flightsim](https://github.com/alphasoc/flightsim)

Flightsim or Network Flight Simulator is a tool made by AlphaSOC to simulate malicious network traffic to test IDS and other network security devices. 

1. Use `git clone https://github.com/alphasoc/flightsim.git` command to clone the main tool directory from their github page.
2. `cd` into the directory, as their tool is written in `go-lang` install it with `sudp apt install golang-go`. Next build the tool using the command `go build -o flightsim main.go`, an executable (in green) is created in the directory.
3. To allow this executable to run globally we move it to `/usr/local/bin` using the command `sudo mv ./flightsim /usr/local/bin/`, this also allows it to run with `sudo` permissions as the same is not possible using alias.
4. Verify installation using `flightsim --help`. 

### Additional configurations

- Add certain fields like `source.ip`, `destination.ip`, `singature` and `event.type` to show critical details on the dashboard making it readable.
- In the `suricata.yaml` search for `stats` and `flow` and comment them, because out-of box suricata acts as a NSM or Network Security Monitor logging everything, so we comment out certain logged details that can clear up the dashboard.
- Use the command `sudo filebeat setup -e` to set up the custom dashboard templates that come filebeat that is best suited for elasticsearch to process.
