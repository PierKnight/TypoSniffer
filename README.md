```
████████╗██╗   ██╗██████╗  ██████╗                   
╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗                  
   ██║    ╚████╔╝ ██████╔╝██║   ██║                  
   ██║     ╚██╔╝  ██╔═══╝ ██║   ██║                  
   ██║      ██║   ██║     ╚██████╔╝                  
   ╚═╝      ╚═╝   ╚═╝      ╚═════╝                   
                                                     
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
```

## Table of Contents

- [Typosquatting Toolkit](#typosquatting-toolkit)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Clone the Repository](#clone-the-repository)
  - [Option 1: Use Poetry Virtual Environment](#option-1-use-poetry-virtual-environment)
  - [Option 2: Install the Wheel](#option-2-install-the-wheel)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Commands](#commands)
  - [`discovery`](#discovery)
  - [`inspect`](#inspect)
  - [`monitor`](#monitor-options-hour-minute)
  - [`domain`](#domain)
  - [`sus-domain`](#sus-domain)
  - [`record`](#record)
  - [`tools`](#tools)
      - [`fuzzing`](#fuzzing)
      - [`dns`](#dns)
      - [`compare_images`](#compare_images)
      - [`compare_domains`](#compare_domains)
      - [`who`](#who)

# Typosquatting Toolkit

A set of tools to generate and detect potential typosquatting attempts targeting one or more domains.  
This toolkit helps security teams monitor domain-space abuse, discover suspicious registrations, and track malicious websites that mimic legitimate brands.

## Features

### 🔠 Generation
- Generate possible typosquatting domains for any target domain.  
- Support for multiple generation algorithms (configurable).  
- Export results for further analysis.

### 🔎 Discovery
- Identify suspicious newly registered domains using [whoisds](https://www.whoisds.com/).  
- Detect and export suspicious domains via DNS queries against a target domain.  
- Flexible configuration of discovery rules and algorithms.    

### 🕵️ Inspection & Monitoring
- Inspect suspicious domains: fetches website screenshots and checks for changes over time.  
- Compare discovered websites against the original domain to highlight suspicious differences.  

### 📢 Notifications
- Send email alerts for newly discovered or updated suspicious domains.  
- Customizable recipients and notification templates.  

### 💾 Data Persistence & Operations
- Store and manage all discovered/inspected data in a database.  
- Daily automated discovery and inspection using a daemon/cron command.  

### ⚙️ Configuration & Extensibility
- Rich configuration options to fine-tune detection and monitoring.  
- Exportable reports for downstream analysis.  

---

## Installation

### Prerequisites
- Python 3.11+  <3.14
- Database supported by SQLAlchemy
- `poetry` installed ([Poetry installation guide](https://python-poetry.org/docs/#installation))
### Clone the Repository
```sh
git clone https://github.com/PierKnight/TypoSniffer.git
cd TypoSniffer
```

### Option 1: Use Poetry Virtual Environment

```sh
#Install dependencies
poetry install


#run CLI directly
poetry run typosniffer

#alternative
#source in virtual environment
eval $(poetry env activate)
```

### Option 2: Install the Wheel
the wheel can be installed from build
```sh
#Build the package
poetry build
#install build
pip install dist/typosniffer-<version>-py3-none-any.whl
```
otherwise download it using:
```sh
#download latest uploaded release
wget "https://github.com/PierKnight/TypoSniffer/releases/download/<version>/typosniffer-<version>-py3-none-any.whl"
#install wheel
pip install typosniffer-<version>-py3-none-any.whl
```

## Technology Stack
- **Python 3.11+**: Core language
- **Poetry**: Dependency management
- **Rich** & **Click**: CLI output
- **Requests**: HTTP requests to APIs
- **Jinja2**: Templating for HTML reports in emails
- **Typeguard**: Type checking for better code quality
- **PlayWright**: Screenshots and web scraping
- **dnspython**: to resolve dns domains
- **textdistance**: tools to compute domain's edit distance
- **sqlalchemy**: for database interaction and ORM
- **whoisit**: retrieve RDAP domain info
- **pydantic**: to ensure consistency across the application
- **imagehash**: image hashing algorithms 
- **python-whois**: retrieve WHOIS domain info
- **torchvision**: PreTrained Models to extract latent space
- **dnstwist**: Generates typosquatting permutations

## Getting Started


### Adding domains
First, you need to register one or more domains to use as a basis for finding similar ones and then inspecting them.

To do this, run: [`typosniffer domain add [DOMAINNAMES]`](#domain)
### Setup database connection
Typosniffer relies on a backend database to store findings and other useful information, so a database must be set up if you want to use the discovery and inspection features.  

Parameters can be provided using environment variables or the [configuration file](#configuration).


### Ready

Now it is possible to discover and inspect suspicious domains using: 
-  [`typosniffer discovery`](#discovery)
- [`typosniffer inspect`](#inspect)

Alternatively, you can run a daemon that executes the two commands every day at a specific hour and minute using [`typosniffer monitor`](#monitor-options-hour-minute).



## Configuration
Typosniffer offers many configurable parameters used throughout
the application.
The file is present at `~/.typosniffer/config.yml` after the first run and it looks like this by default:
```yml
database:
  drivername: postgresql+psycopg2
  username: postgres
  password: postgres
  host: localhost
  port: 5432
  database: postgres
discovery:
  updating_workers: 4
  discovery_workers: 4
  days: 1
  clear_days: null
  criteria:
    damerau_levenshtein: 1
    hamming: null
    jaro: 0.9
    jaro_winkler: null
    levenshtein: null
    tf_idf: null
    tf_idf_ngram:
    - 1
    - 2
  whois_workers: 10
  requests_per_minute: 10
inspection:
  screenshot_dir: /home/kali/.typosniffer/screenshots
  page_load_timeout: 30
  hash_threshold: 6
  max_workers: 4
email: null
```
In this README, parameters are referenced like this:
`config.database.username` has value `postgres`.

To learn more, see [Configuration](src/typosniffer/config/config.py).

## Commands

### `discovery`
This command:
1. Scans the last '`config.discovery.days`' days of registered domains captured from whoids.com, using the algorithms and respective thresholds defined in config `config.discovery.criteria` to identify suspicious domains.
2. Gathers additional information using RDAP; if that fails, it falls back to WHOIS.
3. Records all collected information in the database for later consultation.
4. If an email is configured in `config.email`, an email will be sent containing all newly discovered suspicious domains.

### `inspect`
This command:
1. Collects all suspicious domains present in the database.
2. For each of them, gathers and saves locally a screenshot of the website page (if it exists) at `<config.inspection.screenshot_dir>/<domain>/<date>.png`.
3. If the screenshot hash differs by more than `config.inspection.hash_threshold` bits, the change is recorded.

- If email is configured in `config.email`, an email will be sent containing all the detected changes and a score from 0 to 1 indicating the similarity to the original site's screenshot.
- If an API key is configured in `config.email.imgbb.api_key`, the email will also include links to the respective screenshots.

## `monitor [OPTIONS] HOUR MINUTE`
Command that runs daemon. Every day at hour `HOUR` and minute `MINUTE` will execute `typosniffer discover` followed by `typosniffer inspect`. Useful for discovering and inspecting new and existing domains on a daily basis.

## `domain`
manage domains

## `sus-domain`
manage suspicious domains

## `record`
manage suspicious domains

## `tools`
Set of additional subcommands

### `fuzzing`
Command that, given a domain as input, generates all possible permutations of likely typosquatting domains. The result is written in JSON or CSV format.
### `dns`
Given a list of DNS servers, attempt to identify and collect (in CSV or JSON) all fuzzed domains using `fuzzing` that resolve successfully.
### `compare_images`
Compare two images with the algorithms used in typosniffer
### `compare_domains`
Compare two domains using the configured sniff criteria, useful
to check if the configured criteria fits the user needs.
### `who`
A simple command that retrieves detailed information about a given domain, using RDAP and falling back to WHOIS when needed.





