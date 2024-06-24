# EnumeRannden 🛠️

Welcome to **EnumeRannden**, a comprehensive automation script for penetration testing and reconnaissance, created by [Rannden-SHA](https://github.com/Rannden-SHA). This tool is designed to streamline and enhance your penetration testing workflow by integrating a variety of essential tools and functionalities into a single script.

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Options](#options)
5. [Main Menu Options](#main-menu-options)
6. [Screenshots](#screenshots)
7. [License](#license)

## Features

- **Automated Enumeration**: Perform various NMAP scans, web service enumeration, OSINT gathering, and more.
- **Payload Generation**: Generate payloads using msfvenom for various platforms.
- **Reverse Shell Generation**: Generate reverse shell commands for multiple programming languages and tools.
- **Hash Cracking**: Detect and crack hashes using Hashcat.
- **Cheatsheets**: Access cheatsheets for common commands and techniques.
- **Dependency Management**: Check and install necessary dependencies automatically.

## Installation

To install the necessary dependencies, run:

```bash
sudo ./EnumeRannden.sh -h
```
This will guide you through checking and installing the required tools.

## Usage
Run the script with the following command:

```bash
sudo ./EnumeRannden.sh [options]
```
## Options
-**c** [file.conf] : Load a configuration file.
-**h** : Show help.

## Main Menu Options
### 1. Configure IP
Set the target host IP and detect its operating system.

### 2. Create Directories
Create the main working directory and its subdirectories.

### 3. NMAP Scans
Perform different types of NMAP scans to enumerate open ports and services.

### 4. Web Tools
Use tools like WhatWeb, Nikto, and Gobuster for web service enumeration.

### 5. OSINT Tools
Use tools like theHarvester, Spiderfoot, and FinalRecon for open source intelligence gathering.

### 6. Exploit Tools
Generate payloads and search for exploits using Searchsploit.

### 7. CheatSheets
Display various cheat sheets for Linux commands, Windows commands, pivoting, and file transfer techniques.

### 8. Hash Crack
Detect hash types and crack hashes using Hashcat.

### 9. Reverse Shell Generator
Generate reverse shell commands for various programming languages and tools.

### 10. Generate Report
Save the results of the enumeration and scanning to a report file.

### 11. Check and Install Dependencies
Check for and install necessary dependencies for the script.

### 12. Save & Exit
Save the current configuration and exit the script.


## Screenshots
### Main Menu

### NMAP Scans

### Web Tools

### OSINT Tools

### Exploit Tools

### Reverse Shell Generator

### Hash Crack

### Generate Report

## License
This project is licensed under the MIT License. See the LICENSE file for details.

**🌟 Thank you for using EnumeRannden! Contributions and feedback are welcome. Feel free to fork this repository and submit pull requests.**
