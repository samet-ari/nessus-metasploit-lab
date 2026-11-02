# Rapport d'analyse de vulnérabilités

*Généré le 2026-10-28 — mode hors-ligne*

**Cible(s) :** 192.168.47.133  
**Vulnérabilités retenues :** 11

## 1. Résumé par sévérité

| Sévérité | Nombre |
|---|---|
| Critique | 9 |
| Élevée | 2 |

## 2. Répartition par type de vulnérabilité

| Type | Nombre |
|---|---|
| Porte dérobée (backdoor) | 3 |
| Authentification faible | 3 |
| Exécution de code à distance | 2 |
| Service obsolète / non corrigé | 2 |
| Faille cryptographique | 1 |

## 3. Détail des vulnérabilités

### [Critique] Debian OpenSSH/OpenSSL Package Random Number Generator Weakness

- **Type :** Faille cryptographique
- **Port / service :** 22/tcp ssh
- **CVE :** CVE-2008-0166
- **CVSS :** 10.0

The remote SSH host keys are predictable.

> **Solution (Nessus) :** Regenerate any weak keys using a fixed version of the OpenSSL library.


### [Critique] DistCC Remote Code Execution [À CONFIRMER]

- **Type :** Exécution de code à distance
- **Port / service :** 3632/tcp distccd
- **CVE :** CVE-2004-2687
- **CVSS :** 10.0

The remote distcc service allows remote command execution.

> **Solution (Nessus) :** Disable distcc or restrict it to trusted hosts.


### [Critique] Root Bind Shell Detected [À CONFIRMER]

- **Type :** Porte dérobée (backdoor)
- **Port / service :** 1524/tcp bindshell
- **CVE :** —
- **CVSS :** 10.0

A bind shell is listening on the remote host.

> **Solution (Nessus) :** Identify and remove the backdoor; rebuild the host.


### [Critique] Samba usermap_script Command Execution [À CONFIRMER]

- **Type :** Exécution de code à distance
- **Port / service :** 139/tcp smb
- **CVE :** CVE-2007-2447
- **CVSS :** 10.0

The remote Samba server allows remote command execution.

> **Solution (Nessus) :** Upgrade Samba and disable the username map script option.


### [Critique] Service Detection - Obsolete Operating System [À CONFIRMER]

- **Type :** Service obsolète / non corrigé
- **Port / service :** 0/tcp general
- **CVE :** —
- **CVSS :** 10.0

The remote operating system is obsolete.

> **Solution (Nessus) :** Upgrade to a supported operating system version.


### [Critique] Telnet Service Cleartext / Default Credentials [À CONFIRMER]

- **Type :** Authentification faible
- **Port / service :** 23/tcp telnet
- **CVE :** —
- **CVSS :** 10.0

The remote telnet service is insecure.

> **Solution (Nessus) :** Disable telnet and use SSH instead.


### [Critique] UnrealIRCd Backdoor Detection

- **Type :** Porte dérobée (backdoor)
- **Port / service :** 6667/tcp irc
- **CVE :** CVE-2010-2075
- **CVSS :** 10.0

The remote IRC server contains a backdoor allowing arbitrary code execution.

> **Solution (Nessus) :** Re-download the software, verify it using the published MD5/SHA1 checksums, and re-install it. Run the service under a non-privileged account.


### [Critique] VNC Server 'password' Password

- **Type :** Authentification faible
- **Port / service :** 5900/tcp vnc
- **CVE :** —
- **CVSS :** 10.0

The remote VNC server is protected with a weak password.

> **Solution (Nessus) :** Secure the VNC service with a strong password.


### [Critique] vsftpd Smiley Face Backdoor [À CONFIRMER]

- **Type :** Porte dérobée (backdoor)
- **Port / service :** 21/tcp ftp
- **CVE :** CVE-2011-2523
- **CVSS :** 10.0

The remote FTP server contains a backdoor.

> **Solution (Nessus) :** Reinstall vsftpd from a trusted source.


### [Élevée] Apache HTTP Server Obsolete Version [À CONFIRMER]

- **Type :** Service obsolète / non corrigé
- **Port / service :** 80/tcp www
- **CVE :** —
- **CVSS :** 7.5

An obsolete web server is running on the remote host.

> **Solution (Nessus) :** Upgrade to a currently supported version of Apache.


### [Élevée] MySQL Unpassworded Account [À CONFIRMER]

- **Type :** Authentification faible
- **Port / service :** 3306/tcp mysql
- **CVE :** —
- **CVSS :** 7.5

The remote database server has weak authentication.

> **Solution (Nessus) :** Set strong passwords on all database accounts.


---
*Rapport généré automatiquement à partir de l'export Nessus. Les explications enrichies par IA doivent être relues avant diffusion.*