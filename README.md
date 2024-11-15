# Yi IOT Camera Vulnerabilities (pending CVE request - CVE-XXXX-XXXXX)

## Overview

This repository documents two critical vulnerabilities discovered in Yi IOT cameras, specifically model **XY-3820**. These vulnerabilities allow remote attackers to execute arbitrary scripts and commands with `root` privileges, potentially compromising the device and any network it's connected to.

- **Vendor**: Yi IOT
- **Product**: XY-3820 Camera
- **Affected Versions**: All versions (no fixed version available)

## Vulnerabilities Summary

### 1. Remote Code Execution (RCE) via `daemon` Process - CVE-XXXX-XXXXX

A vulnerability exists in the `daemon` process of the Yi IOT XY-3820 camera, which exposes a TCP service on port **6789**. This service lacks proper input validation, allowing attackers to execute arbitrary scripts present on the device by sending specially crafted TCP requests using directory traversal (`..`) techniques.

- **Vulnerability Type**: Remote Code Execution (RCE)
- **Attack Vector**: Remote, via TCP port 6789
- **Impact**: Allows remote attackers to execute scripts, potentially causing Denial of Service (DoS) or exposing additional ports for further exploitation.
- **Affected Component**: `daemon` binary, TCP service on port 6789

![image](https://github.com/user-attachments/assets/16249bdc-672e-4563-97d9-e6482124ab5a)


### 2. Remote Command Execution via `/usr/bin/cmd` - CVE-XXXX-XXXXX

A second vulnerability was discovered in the `/usr/bin/cmd` binary. When executed, this binary opens a TCP service on port **999**, listening on all interfaces (`0.0.0.0`). The service accepts commands followed by the delimiter `$$boundary\r\n`, executing them with `root` privileges. This allows attackers to run arbitrary system commands remotely.

- **Vulnerability Type**: Remote Code Execution (RCE)
- **Attack Vector**: Remote, via TCP port 999
- **Impact**: Allows remote attackers to gain `root` access and execute arbitrary commands, leading to full device compromise.
- **Affected Component**: `/usr/bin/cmd` binary, TCP service on port 999

![Pasted image 20241113042255](https://github.com/user-attachments/assets/95a9a152-11c2-48cf-82f4-04908d18eaa9)


## Exploitation Chain

By chaining these two vulnerabilities, an attacker can achieve Remote Command Execution (RCE) with `root` privileges on the affected cameras:

1. **Step 1**: Exploit the `daemon` process on port 6789 to trigger the execution of the `/usr/bin/cmd` service.
2. **Step 2**: Use the TCP service on port 999 to execute arbitrary Bash commands with `root` privileges.

## Proof of Concept (PoC)

> **⚠️ Disclaimer**: The following proof of concept is provided for educational purposes only. Unauthorized access to devices that you do not own or have explicit permission to test is illegal.

### Prerequisites

- An reachable Yi IOT XY-3820 camera.
- A tool like `netcat` or `telnet` to send TCP requests.

The camera exposes both an FTP service and a TCP service on port 6789, which can be confirmed by performing a network scan with Nmap:
![Pasted image 20241115115116](https://github.com/user-attachments/assets/ffedc008-2182-4dea-a32f-52c665705f64)

By chaining both vulnerabilities, an attacker can compromise a Yi IOT camera by achieving Remote Code Execution (RCE). Here’s how this can be exploited:

### Step 1: Exploiting the Vulnerability in the daemon Process
The attacker exploits the first vulnerability to trigger the execution of the /usr/bin/cmd binary via the daemon process.
To do this, the attacker sends a crafted TCP packet to port 6789 containing the string ../../../usr/bin/cmd, which allows the attacker to execute the cmd binary by bypassing access controls using relative paths.
The following ncat command can be used to send the malicious TCP request:
![Pasted image 20241115120127](https://github.com/user-attachments/assets/ba25c055-b59c-4d08-a144-609cfd6422eb)


This triggers the execution of the cmd binary on the camera.


### Step 2: Verifying the Exposure of the New Service on Port 999
Once the script is executed, a new TCP service is exposed on port 999, confirming that the exploitation was successful and the camera has been compromised. This can be verified with a subsequent Nmap scan: 
![Pasted image 20241115120034](https://github.com/user-attachments/assets/c5c1562c-18e1-495f-8f76-819a87de543e)

The attacker can now interact with the exposed service on port 999.

### Execution via the /usr/bin/cmd Binary
Once launched, the /usr/bin/cmd binary listens on the interface 0.0.0.0 and accepts incoming connections on port 999. The service allows the attacker to execute arbitrary Bash commands with root privileges.

The attacker can connect to port 999 and execute commands such as:

![Pasted image 20241115120240](https://github.com/user-attachments/assets/832b6f1a-2ffa-42d5-9821-d24bae902271)

**Example of FTP Access:** To verify that the command executed successfully, the attacker may also connect to the camera’s FTP service. This can demonstrate that the command has been executed, but it’s important to note that the attacker can now perform a wide range of actions, including installing malware or retrieving files, not just viewing the file system.

bash
Copier le code
# Example FTP session showing command execution confirmation
![Pasted image 20241115120718](https://github.com/user-attachments/assets/cef6b07c-f08b-4747-b542-008d60d7216f)

# File created as part of the command execution
In this case, the FTP service is simply an example to show that the attack was successful. The attacker can now use the second RCE to install malicious files, retrieve sensitive information, or perform any other arbitrary actions on the camera.

## Mitigation
Currently, no official patch is available from Yi IOT. As a temporary measure, it is recommended to:
- **Restrict Network Access:** Block incoming traffic on ports 6789 and 999 using a firewall.
- **Isolate Affected Devices:** Place affected cameras on a separate VLAN to limit potential lateral movement by attackers.
- **Monitor Network Traffic:** Regularly review network logs for unusual activity, especially traffic targeting ports 6789 and 999.

## Disclaimer
This information is provided "as is" without any warranty. The author is not responsible for any misuse of the vulnerabilities documented here. Always ensure you have permission before testing any system for vulnerabilities. This README provides a comprehensive overview of the vulnerabilities, including a proof of concept, mitigation recommendations, and relevant details for anyone looking to understand the impact and exploitation methods. Adjust the CVE IDs and URLs once they are officially assigned.

## Credits
Discovered by **Yassine Damiri**.
