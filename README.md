<h1 align="center">MaxPhisher - Deobfuscated</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-green?style=for-the-badge">
  <img src="https://img.shields.io/github/stars/KasRoudra/MaxPhisher?style=for-the-badge&color=orange">
  <img src="https://img.shields.io/github/forks/KasRoudra/MaxPhisher?color=cyan&style=for-the-badge&color=purple">
  <img src="https://img.shields.io/github/watchers/KasRoudra/MaxPhisher?color=cyan&style=for-the-badge&color=purple">
  <img src="https://img.shields.io/github/issues/KasRoudra/MaxPhisher?color=red&style=for-the-badge">
  <img src="https://img.shields.io/github/license/KasRoudra/MaxPhisher?style=for-the-badge&color=blue">
  <img src="https://hits.dwyl.com/KasRoudra/MaxPhisher.svg" width="140" height="28">
<br>
<br>
  <img src="https://img.shields.io/badge/Author-KasRoudra-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Open%20Source-80%25-cyan?style=flat-square">
  <img src="https://img.shields.io/badge/Made%20in-Bangladesh-green?colorA=%23ff0000&colorB=%23017e40&style=flat-square">
  <img src="https://img.shields.io/badge/Written%20In-Python-blue?style=flat-square">
</p>


### [√] Description :

***A python phishing script for login phishing, image phishing, video phishing and many more***

### [+] Installation

##### Install primary dependencies (git, python)

 - For Debian (Ubuntu, Kali-Linux, Parrot)
    - ```sudo apt install git python3 php openssh-client -y```
 - For Arch (Manjaro)
    - ```sudo pacman -S git python3 php openssh --noconfirm```
 - For Redhat(Fedora)
    - ```sudo dnf install git python3 php openssh -y```
 - For Termux
    - ```pkg install git python3 php openssh -y```

##### Clone this repository

 - ```git clone https://github.com/KasRoudra/MaxPhisher```

##### Enter the directory
 - ```cd MaxPhisher```

##### Install all modules
 - ```pip3 install -r files/requirements.txt```

##### Run the tool
 - ```python3 maxphisher.py```

#### Or, directly run
```
wget https://raw.githubusercontent.com/KasRoudra/MaxPhisher/main/MaxPhisher.py && python3 maxphisher.py

```

### Pip
 - `pip3 install maxphisher` [For Termux]
 - `sudo pip3 install maxphisher` [For Linux]
 - `maxphisher`

### Docker

 - `sudo docker pull kasroudra/maxphisher`
 - `sudo docker run --rm -it kasroudra/maxphisher`

#### Options

```
usage: maxphisher.py [-h] [-p PORT] [-t TYPE] [-o OPTION] [-T TUNNELER]
                     [-r REGION] [-S SUBDOMAIN] [-d DIRECTORY] [-f FEST]
                     [-i YTID] [-u URL] [-s DURATION] [--noupdate]

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  MaxPhisher's server port [Default : 8080]
  -t TYPE, --type TYPE  MaxPhisher's phishing type index [Default : null]
  -o OPTION, --option OPTION
                        MaxPhisher's template index [Default : null]
  -T TUNNELER, --tunneler TUNNELER
                        Tunneler to be chosen while url shortening [Default :
                        Cloudflared]
  -r REGION, --region REGION
                        Region for ngrok and loclx [Default: auto]
  -S SUBDOMAIN, --subdomain SUBDOMAIN
                        Subdomain for ngrok and loclx [Pro Account] (Default:
                        null)
  -d DIRECTORY, --directory DIRECTORY
                        Directory where media files will be saved [Default :
                        /sdcard/Media]
  -f FEST, --fest FEST  Festival name for fest template [Default: Birthday]
  -i YTID, --ytid YTID  Youtube video ID for yttv template [Default :
                        6hHmkInZkMQ (NASA Video)]
  -u URL, --url URL     Redirection url for ip-tracking or login phishing
                        [Default : null]
  -s DURATION, --duration DURATION
                        Media duration while capturing [Default : 5000(ms)]
  --noupdate            Skip update checking [Default : False]
```

### Features:

 - Multi platform (Supports most linux)
 - 100+ templates
 - Concurrent 4 tunneling (Ngrok, Cloudflared and LocalXpose, LocalHostRun)
 - OTP Support
 - Credentials mailing
 - Easy to use
 - Possible error diagnoser
 - Built-in masking of URL
 - Custom masking of URL
 - URL Shadowing
 - Portable file (Can be run from any directory)
 - Get IP Address and many other details along with login credentials


### Requirements

 - `Python(3)`
   - `requests`
   - `bs4`
 - `PHP`
 - `SSH`
 - 200MB storage
 
If not found, php, ssh and python modoules will be installed on first run

#### Tested on

 - `Termux`
 - `Ubuntu`
 - `Kali-Linux`
 - `Arch`
 - `Fedora`
 - `Manjaro`

## Usage

1. Run the script
2. Choose a Website
3. Wait sometimes for setting up all
4. Send the generated link to victim
5. Wait for victim login. As soon as he/she logs in, credentials will be captured

<h1 align="center">Example</h1>

![MaxPhisher](https://raw.githubusercontent.com/KasRoudra/MaxPhisher/main/files/maxphisher.gif)

 
## [!] Disclaimer
***This tool is developed for educational purposes. Here it demonstrates how phishing works. If anybody wants to gain unauthorized access to someones social media, he/she may try out this at his/her own risk. You have your own responsibilities and you are liable to any damage or violation of laws by this tool. The author is not responsible for any misuse of MaxPhisher!***

### This repository is open source to help others. So if you wish to copy, consider giving credit!

## Credits:
[PyPhisher](https://github.com/KasRoudra/PyPhisher)
[CamHacker](https://github.com/KasRoudra/CamHacker)
[VidPhisher](https://github.com/KasRoudra/VidPhisher)
[IP-Tracker](https://github.com/KasRoudra/IP-Tracker)
[Storm-Breaker](https://github.com/ultrasecurity/Storm-Breaker)
[Seeker](https://github.com/thewhiteh4t/seeker)

## [~] Find Me on :

- [![Github](https://img.shields.io/badge/Github-KasRoudra-green?style=for-the-badge&logo=github)](https://github.com/KasRoudra)

- [![Gmail](https://img.shields.io/badge/Gmail-KasRoudra-green?style=for-the-badge&logo=gmail)](mailto:kasroudrakrd@gmail.com)

- [![Facebook](https://img.shields.io/badge/Facebook-KasRoudra-green?style=for-the-badge&logo=facebook)](https://facebook.com/KasRoudra)

- [![Messenger](https://img.shields.io/badge/Messenger-KasRoudra-green?style=for-the-badge&logo=messenger)](https://m.me/KasRoudra)

