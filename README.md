# What the Hash!?

[![Go Reference](https://pkg.go.dev/badge/github.com/f0x4n6/wth.svg)](https://pkg.go.dev/github.com/f0x4n6/wth)
[![Go Report Card](https://goreportcard.com/badge/github.com/f0x4n6/wth?style=flat-square)](https://goreportcard.com/report/github.com/f0x4n6/wth)
[![Release](https://img.shields.io/github/release/f0x4n6/wth.svg?style=flat-square)](https://github.com/f0x4n6/wth/releases/latest)

**What the Hash!?** is a simple hash reverse lookup. It searches a database of [270+](https://github.com/s0md3v/Bolt/blob/master/db/hashes.json) hash algorithms for the possible source of the given hash sum and outputs all found matches in [hashcat](https://hashcat.net/hashcat/) notation.

```console
go install github.com/f0x4n6/wth@latest
```

## Usage
```console
$ wth HASHSUM
```

## Algorithms
```
1Password(Agile Keychain)
1Password(Cloud Keychain)
Adler-32
AIX(smd5)
AIX(ssha1)
AIX(ssha256)
AIX(ssha512)
Android FDE 4.3
Android PIN
Apache MD5
bcrypt
bcrypt(SHA-256)
BigCrypt
Blowfish(OpenBSD)
BSDi Crypt
Cisco Type 4
Cisco Type 7
Cisco Type 8
Cisco Type 9
Cisco VPN Client(PCF-File)
Cisco-ASA(MD5)
Cisco-IOS(MD5)
Cisco-IOS(SHA-256)
Cisco-PIX(MD5)
Citrix Netscaler
Clavister Secure Gateway
CRAM-MD5
CRC-16
CRC-16-CCITT
CRC-24
CRC-32
CRC-32B
CRC-64
CRC-96(ZIP)
Crypt16
CryptoCurrency(Adress)
CryptoCurrency(PrivateKey)
Dahua
DES(Oracle)
DES(Unix)
DEScrypt
Django(bcrypt)
Django(bcrypt-SHA256)
Django(DES Crypt Wrapper)
Django(MD5)
Django(PBKDF2-HMAC-SHA1)
Django(PBKDF2-HMAC-SHA256)
Django(SHA-1)
Django(SHA-256)
Django(SHA-384)
DNSSEC(NSEC3)
Domain Cached Credentials
Domain Cached Credentials 2
Double MD5
Double SHA-1
Drupal > v7.x
Eggdrop IRC Bot
ELF-32
EPi
EPiServer 6.x < v4
EPiServer 6.x v4
Fairly Secure Hashed Password
FCS-16
FCS-32
Fletcher-32
FNV-132
FNV-164
Fortigate(FortiOS)
FreeBSD MD5
GHash-32-3
GHash-32-5
GOST CryptoPro S-Box
GOST R 34.11-94
GRUB 2
Half MD5
HAS-160
Haval-128
Haval-160
Haval-192
Haval-224
Haval-256
HMAC-MD5 (key = $pass)
HMAC-MD5 (key = $salt)
HMAC-SHA1 (key = $pass)
HMAC-SHA1 (key = $salt)
HMAC-SHA256 (key = $pass)
HMAC-SHA256 (key = $salt)
HMAC-SHA512 (key = $pass)
HMAC-SHA512 (key = $salt)
hMailServer
IKE-PSK MD5
IKE-PSK SHA1
IP.Board v2+
IPMI2 RAKP HMAC-SHA1
iSCSI CHAP Authentication
Joaat
Joomla < v2.5.18
Joomla v2.5.18
Juniper Netscreen/SSG(ScreenOS)
Kerberos 5 AS-REQ Pre-Auth
Lastpass
LDAP(SSHA-512)
Lineage II C4
LinkedIn
LM
Lotus Notes/Domino 5
Lotus Notes/Domino 6
Lotus Notes/Domino 8
MangosWeb Enhanced CMS
MD2
MD4
MD5
MD5 Crypt
md5($pass.$salt)
md5($pass.md5($salt))
md5($salt.$pass)
md5($salt.$pass.$salt)
md5($salt.md5($pass))
md5($salt.md5($pass.$salt))
md5($salt.md5($salt.$pass))
md5($salt.unicode($pass))
md5($username.0.$pass)
MD5(APR)
MD5(Chap)
md5(md5($pass).md5($salt))
md5(md5($salt).$pass)
md5(md5(md5($pass)))
md5(sha1($pass))
md5(strtoupper(md5($pass)))
md5(unicode($pass).$salt)
md5apr1
MediaWiki
Microsoft MSTSC(RDP-File)
Microsoft Office 2007
Microsoft Office 2010
Microsoft Office 2013
Microsoft Office 2003 (MD5+RC4)
Microsoft Office 2003 (MD5+RC4) collider-mode #1
Microsoft Office 2003 (MD5+RC4) collider-mode #2
Microsoft Office 2003 (SHA1+RC4)
Microsoft Office 2003 (SHA1+RC4) collider-mode #1
Microsoft Office 2003 (SHA1+RC4) collider-mode #2
Microsoft Outlook PST
Minecraft(AuthMe Reloaded)
Minecraft(xAuth)
MSSQL(2000)
MSSQL(2005)
MSSQL(2008)
MSSQL(2012)
MSSQL(2014)
MyBB v1.2+
MySQL Challenge-Response Authentication (SHA1)
MySQL323
MySQL4.1
MySQL5.x
NetNTLMv1-VANILLA / NetNTLMv1+ESS
NetNTLMv2
Netscape LDAP SHA
Netscape LDAP SSHA
nsldaps
NTHash(FreeBSD Variant)
NTLM
Oracle 11g/12c
Oracle 7-10g
osCommerce
OSX v10.4
OSX v10.5
OSX v10.6
OSX v10.7
OSX v10.8
OSX v10.9
Palshop CMS
PBKDF2(Atlassian)
PBKDF2(Cryptacular)
PBKDF2(Dwayne Litzenberger)
PBKDF2-HMAC-SHA256(PHP)
PBKDF2-SHA1(Generic)
PBKDF2-SHA256(Generic)
PBKDF2-SHA512(Generic)
PDF 1.4 - 1.6 (Acrobat 5 - 8)
PeopleSoft
PHPass' Portable Hash
phpBB v3.x
PHPS
PostgreSQL Challenge-Response Authentication (MD5)
PostgreSQL MD5
PrestaShop
RACF
RAdmin v2.x
Redmine Project Management Web App
RIPEMD-128
RIPEMD-160
RIPEMD-256
RIPEMD-320
Salsa10
Salsa20
SAM(LM_Hash:NT_Hash)
SAP CODVN B (BCODE)
SAP CODVN F/G (PASSCODE)
SAP CODVN H (PWDSALTEDHASH) iSSHA-1
SCRAM Hash
scrypt
SHA-1
SHA-1 Crypt
SHA-1(Base64)
SHA-1(Oracle)
SHA-224
SHA-256
SHA-256 Crypt
SHA-384
SHA-512
SHA-512 Crypt
sha1($pass.$salt)
sha1($salt.$pass)
sha1($salt.$pass.$salt)
sha1($salt.unicode($pass))
sha1(md5($pass))
sha1(sha1(sha1($pass)))
sha1(unicode($pass).$salt)
sha256($pass.$salt)
sha256($salt.$pass)
sha256($salt.unicode($pass))
sha256(unicode($pass).$salt)
SHA3-224
SHA3-256
SHA3-384
SHA3-512
sha512($pass.$salt)
sha512($salt.$pass)
sha512($salt.unicode($pass))
sha512(unicode($pass).$salt)
Siemens-S7
SipHash
Skein-1024
Skein-1024(384)
Skein-1024(512)
Skein-256
Skein-256(128)
Skein-256(160)
Skein-256(224)
Skein-512
Skein-512(128)
Skein-512(160)
Skein-512(224)
Skein-512(256)
Skein-512(384)
Skype
SMF v1.1
Snefru-128
Snefru-256
SSHA-1(Base64)
SSHA-512(Base64)
Sun MD5 Crypt
Sybase ASE
Tiger-128
Tiger-160
Tiger-192
Traditional DES
vBulletin < v3.8.5
vBulletin v3.8.5
Ventrilo
VNC
WebEdition CMS
Whirlpool
Woltlab Burning Board 3.x
Woltlab Burning Board 4.x
Wordpress v2.6.2
Wordpress v2.6.0/2.6.1
XOR-32
xt:Commerce
ZipMonster 
```

## License
Released under the [MIT License](LICENSE.md).