// Package database implements the data reverse lookup.
//
// Source: https://github.com/s0md3v/Bolt/blob/master/db/hashes.json
package database

import (
	"regexp"
	"strings"
)

// Entry of data pattern.
type Entry struct {
	// Hash regex.
	Regex string
	// Hash names.
	Names []string
}

// Entries of data patterns.
var Entries = []Entry{
	{
		"^[a-f0-9]{4}$",
		[]string{
			"CRC-16",
			"CRC-16-CCITT",
			"FCS-16",
		},
	},
	{
		"^[a-f0-9]{8}$",
		[]string{
			"Adler-32",
			"CRC-32B",
			"FCS-32",
			"GHash-32-3",
			"GHash-32-5",
			"FNV-132",
			"Fletcher-32",
			"Joaat",
			"ELF-32",
			"XOR-32",
		},
	},
	{
		"^[a-f0-9]{6}$",
		[]string{
			"CRC-24",
		},
	},
	{
		"^(\\$crc32\\$[a-f0-9]{8}.)?[a-f0-9]{8}$",
		[]string{
			"CRC-32",
		},
	},
	{
		"^\\+[a-z0-9\\/.]{12}$",
		[]string{
			"Eggdrop IRC Bot",
		},
	},
	{
		"^[a-z0-9\\/.]{13}$",
		[]string{
			"DES(Unix)",
			"Traditional DES",
			"DEScrypt",
		},
	},
	{
		"^[a-f0-9]{16}$",
		[]string{
			"MySQL323",
			"DES(Oracle)",
			"Half MD5",
			"Oracle 7-10g",
			"FNV-164",
			"CRC-64",
		},
	},
	{
		"^[a-z0-9\\/.]{16}$",
		[]string{
			"Cisco-PIX(MD5)",
		},
	},
	{
		"^\\([a-z0-9\\/+]{20}\\)$",
		[]string{
			"Lotus Notes/Domino 6",
		},
	},
	{
		"^_[a-z0-9\\/.]{19}$",
		[]string{
			"BSDi Crypt",
		},
	},
	{
		"^[a-f0-9]{24}$",
		[]string{
			"CRC-96(ZIP)",
		},
	},
	{
		"^[a-z0-9\\/.]{24}$",
		[]string{
			"Crypt16",
		},
	},
	{
		"^(\\$md2\\$)?[a-f0-9]{32}$",
		[]string{
			"MD2",
		},
	},
	{
		"^[a-f0-9]{32}(:.+)?$",
		[]string{
			"MD5",
			"MD4",
			"Double MD5",
			"LM",
			"RIPEMD-128",
			"Haval-128",
			"Tiger-128",
			"Skein-256(128)",
			"Skein-512(128)",
			"Lotus Notes/Domino 5",
			"Skype",
			"ZipMonster",
			"PrestaShop",
			"md5(md5(md5($pass)))",
			"md5(strtoupper(md5($pass)))",
			"md5(sha1($pass))",
			"md5($pass.$salt)",
			"md5($salt.$pass)",
			"md5(unicode($pass).$salt)",
			"md5($salt.unicode($pass))",
			"HMAC-MD5 (key = $pass)",
			"HMAC-MD5 (key = $salt)",
			"md5(md5($salt).$pass)",
			"md5($salt.md5($pass))",
			"md5($pass.md5($salt))",
			"md5($salt.$pass.$salt)",
			"md5(md5($pass).md5($salt))",
			"md5($salt.md5($salt.$pass))",
			"md5($salt.md5($pass.$salt))",
			"md5($username.0.$pass)",
		},
	},
	{
		"^(\\$snefru\\$)?[a-f0-9]{32}$",
		[]string{
			"Snefru-128",
		},
	},
	{
		"^(\\$NT\\$)?[a-f0-9]{32}$",
		[]string{
			"NTLM",
		},
	},
	{
		"^([^\\\\\\/:*?\"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\\\\/:*?\"<>|]{1,20})?$",
		[]string{
			"Domain Cached Credentials",
		},
	},
	{
		"^([^\\\\\\/:*?\"<>|]{1,20}:)?(\\$DCC2\\$10240#[^\\\\\\/:*?\"<>|]{1,20}#)?[a-f0-9]{32}$",
		[]string{
			"Domain Cached Credentials 2",
		},
	},
	{
		"^{SHA}[a-z0-9\\/+]{27}=$",
		[]string{
			"SHA-1(Base64)",
			"Netscape LDAP SHA",
		},
	},
	{
		"^\\$1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}(:.*)?$",
		[]string{
			"MD5 Crypt",
			"Cisco-IOS(MD5)",
			"FreeBSD MD5",
		},
	},
	{
		"^0x[a-f0-9]{32}$",
		[]string{
			"Lineage II C4",
		},
	},
	{
		"^\\$H\\$[a-z0-9\\/.]{31}$",
		[]string{
			"phpBB v3.x",
			"Wordpress v2.6.0/2.6.1",
			"PHPass' Portable Hash",
		},
	},
	{
		"^\\$P\\$[a-z0-9\\/.]{31}$",
		[]string{
			"Wordpress \u2265 v2.6.2",
			"Joomla \u2265 v2.5.18",
			"PHPass' Portable Hash",
		},
	},
	{
		"^[a-f0-9]{32}:[a-z0-9]{2}$",
		[]string{
			"osCommerce",
			"xt:Commerce",
		},
	},
	{
		"^\\$apr1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}$",
		[]string{
			"MD5(APR)",
			"Apache MD5",
			"md5apr1",
		},
	},
	{
		"^{smd5}[a-z0-9$\\/.]{31}$",
		[]string{
			"AIX(smd5)",
		},
	},
	{
		"^[a-f0-9]{32}:[a-f0-9]{32}$",
		[]string{
			"WebEdition CMS",
		},
	},
	{
		"^[a-f0-9]{32}:.{5}$",
		[]string{
			"IP.Board \u2265 v2+",
		},
	},
	{
		"^[a-f0-9]{32}:.{8}$",
		[]string{
			"MyBB \u2265 v1.2+",
		},
	},
	{
		"^[a-z0-9]{34}$",
		[]string{
			"CryptoCurrency(Address)",
		},
	},
	{
		"^[a-f0-9]{40}(:.+)?$",
		[]string{
			"SHA-1",
			"Double SHA-1",
			"RIPEMD-160",
			"Haval-160",
			"Tiger-160",
			"HAS-160",
			"LinkedIn",
			"Skein-256(160)",
			"Skein-512(160)",
			"MangosWeb Enhanced CMS",
			"sha1(sha1(sha1($pass)))",
			"sha1(md5($pass))",
			"sha1($pass.$salt)",
			"sha1($salt.$pass)",
			"sha1(unicode($pass).$salt)",
			"sha1($salt.unicode($pass))",
			"HMAC-SHA1 (key = $pass)",
			"HMAC-SHA1 (key = $salt)",
			"sha1($salt.$pass.$salt)",
		},
	},
	{
		"^\\*[a-f0-9]{40}$",
		[]string{
			"MySQL5.x",
			"MySQL4.1",
		},
	},
	{
		"^[a-z0-9]{43}$",
		[]string{
			"Cisco-IOS(SHA-256)",
		},
	},
	{
		"^{SSHA}[a-z0-9\\/+]{38}==$",
		[]string{
			"SSHA-1(Base64)",
			"Netscape LDAP SSHA",
			"nsldaps",
		},
	},
	{
		"^[a-z0-9=]{47}$",
		[]string{
			"Fortigate(FortiOS)",
		},
	},
	{
		"^[a-f0-9]{48}$",
		[]string{
			"Haval-192",
			"Tiger-192",
			"SHA-1(Oracle)",
			"OSX v10.4",
			"OSX v10.5",
			"OSX v10.6",
		},
	},
	{
		"^[a-f0-9]{51}$",
		[]string{
			"Palshop CMS",
		},
	},
	{
		"^[a-z0-9]{51}$",
		[]string{
			"CryptoCurrency(PrivateKey)",
		},
	},
	{
		"^{ssha1}[0-9]{2}\\$[a-z0-9$\\/.]{44}$",
		[]string{
			"AIX(ssha1)",
		},
	},
	{
		"^0x0100[a-f0-9]{48}$",
		[]string{
			"MSSQL(2005)",
			"MSSQL(2008)",
		},
	},
	{
		"^(\\$md5,rounds=[0-9]+\\$|\\$md5\\$rounds=[0-9]+\\$|\\$md5\\$)[a-z0-9\\/.]{0,16}(\\$|\\$\\$)[a-z0-9\\/.]{22}$",
		[]string{
			"Sun MD5 Crypt",
		},
	},
	{
		"^[a-f0-9]{56}$",
		[]string{
			"SHA-224",
			"Haval-224",
			"SHA3-224",
			"Skein-256(224)",
			"Skein-512(224)",
		},
	},
	{
		"^(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$",
		[]string{
			"Blowfish(OpenBSD)",
			"Woltlab Burning Board 4.x",
			"bcrypt",
		},
	},
	{
		"^[a-f0-9]{40}:[a-f0-9]{16}$",
		[]string{
			"Android PIN",
		},
	},
	{
		"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$",
		[]string{
			"Oracle 11g/12c",
		},
	},
	{
		"^\\$bcrypt-sha256\\$(2[axy]|2)\\,[0-9]+\\$[a-z0-9\\/.]{22}\\$[a-z0-9\\/.]{31}$",
		[]string{
			"bcrypt(SHA-256)",
		},
	},
	{
		"^[a-f0-9]{32}:.{3}$",
		[]string{
			"vBulletin < v3.8.5",
		},
	},
	{
		"^[a-f0-9]{32}:.{30}$",
		[]string{
			"vBulletin \u2265 v3.8.5",
		},
	},
	{
		"^(\\$snefru\\$)?[a-f0-9]{64}$",
		[]string{
			"Snefru-256",
		},
	},
	{
		"^[a-f0-9]{64}(:.+)?$",
		[]string{
			"SHA-256",
			"RIPEMD-256",
			"Haval-256",
			"GOST R 34.11-94",
			"GOST CryptoPro S-Box",
			"SHA3-256",
			"Skein-256",
			"Skein-512(256)",
			"Ventrilo",
			"sha256($pass.$salt)",
			"sha256($salt.$pass)",
			"sha256(unicode($pass).$salt)",
			"sha256($salt.unicode($pass))",
			"HMAC-SHA256 (key = $pass)",
			"HMAC-SHA256 (key = $salt)",
		},
	},
	{
		"^[a-f0-9]{32}:[a-z0-9]{32}$",
		[]string{
			"Joomla < v2.5.18",
		},
	},
	{
		"^[a-f-0-9]{32}:[a-f-0-9]{32}$",
		[]string{
			"SAM(LM_Hash:NT_Hash)",
		},
	},
	{
		"^(\\$chap\\$0\\*)?[a-f0-9]{32}[\\*:][a-f0-9]{32}(:[0-9]{2})?$",
		[]string{
			"MD5(Chap)",
			"iSCSI CHAP Authentication",
		},
	},
	{
		"^\\$episerver\\$\\*0\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{27,28}$",
		[]string{
			"EPiServer 6.x < v4",
		},
	},
	{
		"^{ssha256}[0-9]{2}\\$[a-z0-9$\\/.]{60}$",
		[]string{
			"AIX(ssha256)",
		},
	},
	{
		"^[a-f0-9]{80}$",
		[]string{
			"RIPEMD-320",
		},
	},
	{
		"^\\$episerver\\$\\*1\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{42,43}$",
		[]string{
			"EPiServer 6.x \u2265 v4",
		},
	},
	{
		"^0x0100[a-f0-9]{88}$",
		[]string{
			"MSSQL(2000)",
		},
	},
	{
		"^[a-f0-9]{96}$",
		[]string{
			"SHA-384",
			"SHA3-384",
			"Skein-512(384)",
			"Skein-1024(384)",
		},
	},
	{
		"^{SSHA512}[a-z0-9\\/+]{96}$",
		[]string{
			"SSHA-512(Base64)",
			"LDAP(SSHA-512)",
		},
	},
	{
		"^{ssha512}[0-9]{2}\\$[a-z0-9\\/.]{16,48}\\$[a-z0-9\\/.]{86}$",
		[]string{
			"AIX(ssha512)",
		},
	},
	{
		"^[a-f0-9]{128}(:.+)?$",
		[]string{
			"SHA-512",
			"Whirlpool",
			"Salsa10",
			"Salsa20",
			"SHA3-512",
			"Skein-512",
			"Skein-1024(512)",
			"sha512($pass.$salt)",
			"sha512($salt.$pass)",
			"sha512(unicode($pass).$salt)",
			"sha512($salt.unicode($pass))",
			"HMAC-SHA512 (key = $pass)",
			"HMAC-SHA512 (key = $salt)",
		},
	},
	{
		"^[a-f0-9]{136}$",
		[]string{
			"OSX v10.7",
		},
	},
	{
		"^0x0200[a-f0-9]{136}$",
		[]string{
			"MSSQL(2012)",
			"MSSQL(2014)",
		},
	},
	{
		"^\\$ml\\$[0-9]+\\$[a-f0-9]{64}\\$[a-f0-9]{128}$",
		[]string{
			"OSX v10.8",
			"OSX v10.9",
		},
	},
	{
		"^[a-f0-9]{256}$",
		[]string{
			"Skein-1024",
		},
	},
	{
		"^grub\\.pbkdf2\\.sha512\\.[0-9]+\\.([a-f0-9]{128,1000}[a-f0-9]{0,1000}[a-f0-9]{0,48}\\.|[0-9]+\\.)?[a-f0-9]{128}$",
		[]string{
			"GRUB 2",
		},
	},
	{
		"^sha1\\$[a-z0-9]+\\$[a-f0-9]{40}$",
		[]string{
			"Django(SHA-1)",
		},
	},
	{
		"^[a-f0-9]{49}$",
		[]string{
			"Citrix Netscaler",
		},
	},
	{
		"^\\$S\\$[a-z0-9\\/.]{52}$",
		[]string{
			"Drupal > v7.x",
		},
	},
	{
		"^\\$5\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{43}$",
		[]string{
			"SHA-256 Crypt",
		},
	},
	{
		"^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$",
		[]string{
			"Sybase ASE",
		},
	},
	{
		"^\\$6\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{86}$",
		[]string{
			"SHA-512 Crypt",
		},
	},
	{
		"^\\$sha\\$[a-z0-9]{1,16}\\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$",
		[]string{
			"Minecraft(AuthMe Reloaded)",
		},
	},
	{
		"^sha256\\$[a-z0-9]+\\$[a-f0-9]{64}$",
		[]string{
			"Django(SHA-256)",
		},
	},
	{
		"^sha384\\$[a-z0-9]+\\$[a-f0-9]{96}$",
		[]string{
			"Django(SHA-384)",
		},
	},
	{
		"^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$",
		[]string{
			"Clavister Secure Gateway",
		},
	},
	{
		"^[a-f0-9]{112}$",
		[]string{
			"Cisco VPN Client(PCF-File)",
		},
	},
	{
		"^[a-f0-9]{1000}[a-f0-9]{329}$",
		[]string{
			"Microsoft MSTSC(RDP-File)",
		},
	},
	{
		"^[^\\\\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\\\\/:*?\"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$",
		[]string{
			"NetNTLMv1-VANILLA / NetNTLMv1+ESS",
		},
	},
	{
		"^([^\\\\\\/:*?\"<>|]{1,20}\\\\)?[^\\\\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\\\\/:*?\"<>|]{1,20}:)?[^\\\\\\/:*?\"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$",
		[]string{
			"NetNTLMv2",
		},
	},
	{
		"^\\$(krb5pa|mskrb5)\\$([0-9]{2})?\\$.+\\$[a-f0-9]{1,}$",
		[]string{
			"Kerberos 5 AS-REQ Pre-Auth",
		},
	},
	{
		"^\\$scram\\$[0-9]+\\$[a-z0-9\\/.]{16}\\$sha-1=[a-z0-9\\/.]{27},sha-256=[a-z0-9\\/.]{43},sha-512=[a-z0-9\\/.]{86}$",
		[]string{
			"SCRAM Hash",
		},
	},
	{
		"^[a-f0-9]{40}:[a-f0-9]{0,32}$",
		[]string{
			"Redmine Project Management Web App",
		},
	},
	{
		"^(.+)?\\$[a-f0-9]{16}$",
		[]string{
			"SAP CODVN B (BCODE)",
		},
	},
	{
		"^(.+)?\\$[a-f0-9]{40}$",
		[]string{
			"SAP CODVN F/G (PASSCODE)",
		},
	},
	{
		"^(.+\\$)?[a-z0-9\\/.+]{30}(:.+)?$",
		[]string{
			"Juniper Netscreen/SSG(ScreenOS)",
		},
	},
	{
		"^0x[a-f0-9]{60}\\s0x[a-f0-9]{40}$",
		[]string{
			"EPi",
		},
	},
	{
		"^[a-f0-9]{40}:[^*]{1,25}$",
		[]string{
			"SMF \u2265 v1.1",
		},
	},
	{
		"^(\\$wbb3\\$\\*1\\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$",
		[]string{
			"Woltlab Burning Board 3.x",
		},
	},
	{
		"^[a-f0-9]{130}(:[a-f0-9]{40})?$",
		[]string{
			"IPMI2 RAKP HMAC-SHA1",
		},
	},
	{
		"^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9-.]+$",
		[]string{
			"Lastpass",
		},
	},
	{
		"^[a-z0-9\\/.]{16}([:$].{1,})?$",
		[]string{
			"Cisco-ASA(MD5)",
		},
	},
	{
		"^\\$vnc\\$\\*[a-f0-9]{32}\\*[a-f0-9]{32}$",
		[]string{
			"VNC",
		},
	},
	{
		"^[a-z0-9]{32}(:([a-z0-9-]+\\.)?[a-z0-9-.]+\\.[a-z]{2,7}:.+:[0-9]+)?$",
		[]string{
			"DNSSEC(NSEC3)",
		},
	},
	{
		"^(user-.+:)?\\$racf\\$\\*.+\\*[a-f0-9]{16}$",
		[]string{
			"RACF",
		},
	},
	{
		"^\\$3\\$\\$[a-f0-9]{32}$",
		[]string{
			"NTHash(FreeBSD Variant)",
		},
	},
	{
		"^\\$sha1\\$[0-9]+\\$[a-z0-9\\/.]{0,64}\\$[a-z0-9\\/.]{28}$",
		[]string{
			"SHA-1 Crypt",
		},
	},
	{
		"^[a-f0-9]{70}$",
		[]string{
			"hMailServer",
		},
	},
	{
		"^[:\\$][AB][:\\$]([a-f0-9]{1,8}[:\\$])?[a-f0-9]{32}$",
		[]string{
			"MediaWiki",
		},
	},
	{
		"^[a-f0-9]{140}$",
		[]string{
			"Minecraft(xAuth)",
		},
	},
	{
		"^\\$pbkdf2(-sha1)?\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{27}$",
		[]string{
			"PBKDF2-SHA1(Generic)",
		},
	},
	{
		"^\\$pbkdf2-sha256\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{43}$",
		[]string{
			"PBKDF2-SHA256(Generic)",
		},
	},
	{
		"^\\$pbkdf2-sha512\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{86}$",
		[]string{
			"PBKDF2-SHA512(Generic)",
		},
	},
	{
		"^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+-]{27}=$",
		[]string{
			"PBKDF2(Cryptacular)",
		},
	},
	{
		"^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{32}$",
		[]string{
			"PBKDF2(Dwayne Litzenberger)",
		},
	},
	{
		"^{FSHP[0123]\\|[0-9]+\\|[0-9]+}[a-z0-9\\/+=]+$",
		[]string{
			"Fairly Secure Hashed Password",
		},
	},
	{
		"^\\$PHPS\\$.+\\$[a-f0-9]{32}$",
		[]string{
			"PHPS",
		},
	},
	{
		"^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{80}$",
		[]string{
			"1Password(Agile Keychain)",
		},
	},
	{
		"^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$",
		[]string{
			"1Password(Cloud Keychain)",
		},
	},
	{
		"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$",
		[]string{
			"IKE-PSK MD5",
		},
	},
	{
		"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$",
		[]string{
			"IKE-PSK SHA1",
		},
	},
	{
		"^[a-z0-9\\/+]{27}=$",
		[]string{
			"PeopleSoft",
		},
	},
	{
		"^crypt\\$[a-f0-9]{5}\\$[a-z0-9\\/.]{13}$",
		[]string{
			"Django(DES Crypt Wrapper)",
		},
	},
	{
		"^(\\$django\\$\\*1\\*)?pbkdf2_sha256\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{44}$",
		[]string{
			"Django(PBKDF2-HMAC-SHA256)",
		},
	},
	{
		"^pbkdf2_sha1\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{28}$",
		[]string{
			"Django(PBKDF2-HMAC-SHA1)",
		},
	},
	{
		"^bcrypt(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$",
		[]string{
			"Django(bcrypt)",
		},
	},
	{
		"^md5\\$[a-f0-9]+\\$[a-f0-9]{32}$",
		[]string{
			"Django(MD5)",
		},
	},
	{
		"^\\{PKCS5S2\\}[a-z0-9\\/+]{64}$",
		[]string{
			"PBKDF2(Atlassian)",
		},
	},
	{
		"^md5[a-f0-9]{32}$",
		[]string{
			"PostgreSQL MD5",
		},
	},
	{
		"^\\([a-z0-9\\/+]{49}\\)$",
		[]string{
			"Lotus Notes/Domino 8",
		},
	},
	{
		"^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\\/+=]{1,}$",
		[]string{
			"scrypt",
		},
	},
	{
		"^\\$8\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$",
		[]string{
			"Cisco Type 8",
		},
	},
	{
		"^\\$9\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$",
		[]string{
			"Cisco Type 9",
		},
	},
	{
		"^\\$office\\$\\*2007\\*[0-9]{2}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{40}$",
		[]string{
			"Microsoft Office 2007",
		},
	},
	{
		"^\\$office\\$\\*2010\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$",
		[]string{
			"Microsoft Office 2010",
		},
	},
	{
		"^\\$office\\$\\*2013\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$",
		[]string{
			"Microsoft Office 2013",
		},
	},
	{
		"^\\$fde\\$[0-9]{2}\\$[a-f0-9]{32}\\$[0-9]{2}\\$[a-f0-9]{32}\\$[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{72}$",
		[]string{
			"Android FDE \u2264 4.3",
		},
	},
	{
		"^\\$oldoffice\\$[01]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{32}$",
		[]string{
			"Microsoft Office \u2264 2003 (MD5+RC4)",
			"Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #1",
			"Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #2",
		},
	},
	{
		"^\\$oldoffice\\$[34]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{40}$",
		[]string{
			"Microsoft Office \u2264 2003 (SHA1+RC4)",
			"Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #1",
			"Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #2",
		},
	},
	{
		"^(\\$radmin2\\$)?[a-f0-9]{32}$",
		[]string{
			"RAdmin v2.x",
		},
	},
	{
		"^{x-issha,\\s[0-9]{4}}[a-z0-9\\/+=]+$",
		[]string{
			"SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
		},
	},
	{
		"^\\$cram_md5\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+=-]{52}$",
		[]string{
			"CRAM-MD5",
		},
	},
	{
		"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$",
		[]string{
			"SipHash",
		},
	},
	{
		"^[a-f0-9]{4,}$",
		[]string{
			"Cisco Type 7",
		},
	},
	{
		"^[a-z0-9\\/.]{13,}$",
		[]string{
			"BigCrypt",
		},
	},
	{
		"^(\\$cisco4\\$)?[a-z0-9\\/.]{43}$",
		[]string{
			"Cisco Type 4",
		},
	},
	{
		"^bcrypt_sha256\\$\\$(2[axy]|2)\\$[0-9]+\\$[a-z0-9\\/.]{53}$",
		[]string{
			"Django(bcrypt-SHA256)",
		},
	},
	{
		"^\\$postgres\\$.[^\\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$",
		[]string{
			"PostgreSQL Challenge-Response Authentication (MD5)",
		},
	},
	{
		"^\\$siemens-s7\\$[0-9]{1}\\$[a-f0-9]{40}\\$[a-f0-9]{40}$",
		[]string{
			"Siemens-S7",
		},
	},
	{
		"^(\\$pst\\$)?[a-f0-9]{8}$",
		[]string{
			"Microsoft Outlook PST",
		},
	},
	{
		"^sha256[:$][0-9]+[:$][a-z0-9\\/+]+[:$][a-z0-9\\/+]{32,128}$",
		[]string{
			"PBKDF2-HMAC-SHA256(PHP)",
		},
	},
	{
		"^(\\$dahua\\$)?[a-z0-9]{8}$",
		[]string{
			"Dahua",
		},
	},
	{
		"^\\$mysqlna\\$[a-f0-9]{40}[:*][a-f0-9]{40}$",
		[]string{
			"MySQL Challenge-Response Authentication (SHA1)",
		},
	},
	{
		"^\\$pdf\\$[24]\\*[34]\\*128\\*[0-9-]{1,5}\\*1\\*(16|32)\\*[a-f0-9]{32,64}\\*32\\*[a-f0-9]{64}\\*(8|16|32)\\*[a-f0-9]{16,64}$",
		[]string{
			"PDF 1.4 - 1.6 (Acrobat 5 - 8)",
		},
	},
}

// Lookup will write the found matches into the returned channel.
//
// The returned channel will be closed at the end of the operation.
func Lookup(v string) <-chan string {
	ch := make(chan string)

	go func(chan<- string) {
		for _, e := range Entries {
			if regexp.MustCompile(e.Regex).MatchString(v) {
				ch <- strings.Join(e.Names, "\n")
			}
		}
		close(ch)
	}(ch)

	return ch
}
