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
- Python 3.13+  
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
#run CLI
typosniffer
```

### Option 2: Build and Install the Wheel

```sh
#Build the package
poetry build
#Install the generated wheel
#(replace dist/typodetector-x.y.z-py3-none-any.whl with your version):
pip install dist/typodetector-*.whl
#Run CLI
typosniffer
```

## Usage


