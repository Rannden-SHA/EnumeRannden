# EnumeRannden 🛠️

![BANNER](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/banner.png)

Welcome to **EnumeRannden**, a comprehensive automation script for penetration testing and reconnaissance, created by **Adrián Gisbert - Aka [Rannden-SHA](https://github.com/Rannden-SHA).** This tool is designed to streamline and enhance your penetration testing workflow by integrating a variety of essential tools and functionalities into a single script.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Options](#options)
5. [Main Menu Options](#main-menu-options)
6. [License](#license)

## Features

- **Automated Enumeration**: Perform various NMAP scans, web service enumeration, OSINT gathering, and more.
- **Payload Generation**: Generate payloads using msfvenom for various platforms.
- **Reverse Shell Generation**: Generate reverse shell commands for multiple programming languages and tools.
- **Hash Cracking**: Detect and crack hashes using Hashcat.
- **Cheatsheets**: Access cheatsheets for common commands and techniques.
- **Dependency Management**: Check and install necessary dependencies automatically.
- **Nuclei Compatibility**: Integrated with Nuclei for advanced OSINT scanning.
- **Improved UI**: Enhanced graphical interface with system and IP information.
- **Download Tools**: New section for downloading tools like Socat, Chisel, Ligolo, WinPEAS, and LinPEAS in various versions.
- **Added to the Path**: The first time the script is executed, it will set up a symlink allowing future executions from anywhere by typing **enumerannden**.
- **Generate a PDF Report**: Now it generates a .txt report and a .pdf report (More aesthetic)
- **Active Directory Tools**: Enumerate Active Directory
- **Post-Explotation**:Manage a reverse shell and enter preset commands for different outputs
- **Port Knocking**: Method of externally opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports
- **Brute Forece Attack**: Hydra
- **Subdomain Scanner**: On Web Tools Submenu
- **Create a custom password dictionary**: through a previous questionnaire.
- **Fixed some bugs**

## Installation

Download the script:

```bash
wget https://github.com/Rannden-SHA/EnumeRannden/blob/main/EnumeRannden.sh
```
Give execution permissions:

```bash
chmod +x ./EnumeRannden.sh
```
To install the necessary dependencies, run:

```bash
./EnumeRannden.sh -h
```
This will guide you through checking and installing the required tools.

Or run the script and select the option 12):
```bash
./EnumeRannden.sh
```

## Usage
Run the script with the following command:

```bash
./EnumeRannden.sh [options]
```
The first time the script is executed, it will set up a symlink allowing future executions from anywhere by typing **enumerannden**.
For future executions just run:

```bash
enumerannden [options]
```

## Options
**-c** [file.conf] : Load a configuration file.

**-h** : Show help.

## Configuration File
### What is the Configuration File?
The configuration file allows you to save the current state of your session, including IP configuration, detected operating system, open ports, and directory paths. This is particularly useful for pausing and resuming work without losing progress.

### How to Save the Configuration File
After setting up your session (configuring IP, creating directories, performing scans), the script automatically saves the configuration to a file in the format session_name.conf within the main directory. You can also manually save the configuration at any point by choosing the "Save & Exit" option from the main menu.

### How to Use the Configuration File
To load a saved session, use the -c option followed by the configuration file name:

```bash
./EnumeRannden.sh -c path_to_config_file.conf
```
This loads all previously saved settings and results, allowing you to seamlessly continue your work from where you left off.

### Why Use the Configuration File?
Efficiency: Save time by avoiding reconfiguration each session.

Consistency: Maintain the same environment and settings across multiple sessions.

Convenience: Easily pause and resume work without losing any progress.

![INFO_PANEL](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/info_panel.png)

## Main Menu Options

![Main](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/main.png)

### 1. Configure IP
Set the target host IP and detect its operating system.

### 2. Create Directories
Create the main working directory and its subdirectories.

### 3. NMAP Scans
Perform different types of NMAP scans to enumerate open ports and services.

![NMAP](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/nmap.png)

### 4. Web Tools
Use tools like WhatWeb, Nikto, and Gobuster for web service enumeration.

![WEB_TOOLS](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/web_tools.png)

### 5. Brute Force Attacks
Brute forces a selected protocol.

### 6. Create a persolaizated passwords dictionary
Create a custom password dictionary through a previous questionnaire.

### 7. Port Knocking
Method of externally opening ports on a firewall by generating a connection attempt on a set of prespecified closed ports.

### 8. OSINT Tools
Use tools like theHarvester, Spiderfoot, and FinalRecon for open source intelligence gathering.

![OSINT_TOOLS](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/osint_tools.png)

### 9. Exploit Tools
Generate payloads and search for exploits using Searchsploit.

![EXPLOIT_TOOLS](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/exploit_tools.png)

### 10. CheatSheets
Display various cheat sheets for Linux commands, Windows commands, pivoting, and file transfer techniques.

### 11. Hash Crack
Detect hash types and crack hashes using Hashcat.

### 12. Active Directory Tools
Enumerate Active Directory.

### 13. Reverse Shell Generator
Generate reverse shell commands for various programming languages and tools.

![REVERSE_SHELL_TOOL](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/reverse_shell_tool.png)

### 14. Post Explotation
Manage a reverse shell and enter preset commands for different outputs.

### 15. Download Tools
Section for downloading tools like Socat, Chisel, Ligolo, WinPEAS, and LinPEAS in various versions.

![DOWNLOAD_TOOLS](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/download_tools.png)

### 16. Generate Report
Save the results of the enumeration and scanning to a report file.

![TEST_REPORT](https://github.com/Rannden-SHA/EnumeRannden/blob/main/Images/report_test.png)

Test_Report: https://github.com/Rannden-SHA/EnumeRannden/blob/main/report_test.pdf

### 17. Check and Install Dependencies
Check for and install necessary dependencies for the script.

### 18. Save & Exit
Save the current configuration and exit the script.


## License
This project is licensed under the MIT License. See the LICENSE file for details.

**🌟 Thank you for using EnumeRannden! Contributions and feedback are welcome. Feel free to fork this repository and submit pull requests.**
