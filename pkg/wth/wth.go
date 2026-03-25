// Package wth implements the What The Hash reverse lookup.
package wth

import (
	"regexp"
	"strings"
)

// The internal database of the hash regex patterns.
//
// Source: https://github.com/s0md3v/Bolt/blob/master/db/hashes.json
var database = []struct {
	Regex string
	Algos []string
}{
	{
		Regex: "^[a-f0-9]{4}$",
		Algos: []string{
			"CRC-16",
			"CRC-16-CCITT",
			"FCS-16",
		},
	},
	{
		Regex: "^[a-f0-9]{8}$",
		Algos: []string{
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
		Regex: "^[a-f0-9]{6}$",
		Algos: []string{
			"CRC-24",
		},
	},
	{
		Regex: "^(\\$crc32\\$[a-f0-9]{8}.)?[a-f0-9]{8}$",
		Algos: []string{
			"CRC-32",
		},
	},
	{
		Regex: "^\\+[a-z0-9\\/.]{12}$",
		Algos: []string{
			"Eggdrop IRC Bot",
		},
	},
	{
		Regex: "^[a-z0-9\\/.]{13}$",
		Algos: []string{
			"DES(Unix)",
			"Traditional DES",
			"DEScrypt",
		},
	},
	{
		Regex: "^[a-f0-9]{16}$",
		Algos: []string{
			"MySQL323",
			"DES(Oracle)",
			"Half MD5",
			"Oracle 7-10g",
			"FNV-164",
			"CRC-64",
		},
	},
	{
		Regex: "^[a-z0-9\\/.]{16}$",
		Algos: []string{
			"Cisco-PIX(MD5)",
		},
	},
	{
		Regex: "^\\([a-z0-9\\/+]{20}\\)$",
		Algos: []string{
			"Lotus Notes/Domino 6",
		},
	},
	{
		Regex: "^_[a-z0-9\\/.]{19}$",
		Algos: []string{
			"BSDi Crypt",
		},
	},
	{
		Regex: "^[a-f0-9]{24}$",
		Algos: []string{
			"CRC-96(ZIP)",
		},
	},
	{
		Regex: "^[a-z0-9\\/.]{24}$",
		Algos: []string{
			"Crypt16",
		},
	},
	{
		Regex: "^(\\$md2\\$)?[a-f0-9]{32}$",
		Algos: []string{
			"MD2",
		},
	},
	{
		Regex: "^[a-f0-9]{32}(:.+)?$",
		Algos: []string{
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
		Regex: "^(\\$snefru\\$)?[a-f0-9]{32}$",
		Algos: []string{
			"Snefru-128",
		},
	},
	{
		Regex: "^(\\$NT\\$)?[a-f0-9]{32}$",
		Algos: []string{
			"NTLM",
		},
	},
	{
		Regex: "^([^\\\\\\/:*?\"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\\\\/:*?\"<>|]{1,20})?$",
		Algos: []string{
			"Domain Cached Credentials",
		},
	},
	{
		Regex: "^([^\\\\\\/:*?\"<>|]{1,20}:)?(\\$DCC2\\$10240#[^\\\\\\/:*?\"<>|]{1,20}#)?[a-f0-9]{32}$",
		Algos: []string{
			"Domain Cached Credentials 2",
		},
	},
	{
		Regex: "^{SHA}[a-z0-9\\/+]{27}=$",
		Algos: []string{
			"SHA-1(Base64)",
			"Netscape LDAP SHA",
		},
	},
	{
		Regex: "^\\$1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}(:.*)?$",
		Algos: []string{
			"MD5 Crypt",
			"Cisco-IOS(MD5)",
			"FreeBSD MD5",
		},
	},
	{
		Regex: "^0x[a-f0-9]{32}$",
		Algos: []string{
			"Lineage II C4",
		},
	},
	{
		Regex: "^\\$H\\$[a-z0-9\\/.]{31}$",
		Algos: []string{
			"phpBB v3.x",
			"Wordpress v2.6.0/2.6.1",
			"PHPass' Portable Hash",
		},
	},
	{
		Regex: "^\\$P\\$[a-z0-9\\/.]{31}$",
		Algos: []string{
			"Wordpress \u2265 v2.6.2",
			"Joomla \u2265 v2.5.18",
			"PHPass' Portable Hash",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:[a-z0-9]{2}$",
		Algos: []string{
			"osCommerce",
			"xt:Commerce",
		},
	},
	{
		Regex: "^\\$apr1\\$[a-z0-9\\/.]{0,8}\\$[a-z0-9\\/.]{22}$",
		Algos: []string{
			"MD5(APR)",
			"Apache MD5",
			"md5apr1",
		},
	},
	{
		Regex: "^{smd5}[a-z0-9$\\/.]{31}$",
		Algos: []string{
			"AIX(smd5)",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:[a-f0-9]{32}$",
		Algos: []string{
			"WebEdition CMS",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:.{5}$",
		Algos: []string{
			"IP.Board \u2265 v2+",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:.{8}$",
		Algos: []string{
			"MyBB \u2265 v1.2+",
		},
	},
	{
		Regex: "^[a-z0-9]{34}$",
		Algos: []string{
			"CryptoCurrency(Address)",
		},
	},
	{
		Regex: "^[a-f0-9]{40}(:.+)?$",
		Algos: []string{
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
		Regex: "^\\*[a-f0-9]{40}$",
		Algos: []string{
			"MySQL5.x",
			"MySQL4.1",
		},
	},
	{
		Regex: "^[a-z0-9]{43}$",
		Algos: []string{
			"Cisco-IOS(SHA-256)",
		},
	},
	{
		Regex: "^{SSHA}[a-z0-9\\/+]{38}==$",
		Algos: []string{
			"SSHA-1(Base64)",
			"Netscape LDAP SSHA",
			"nsldaps",
		},
	},
	{
		Regex: "^[a-z0-9=]{47}$",
		Algos: []string{
			"Fortigate(FortiOS)",
		},
	},
	{
		Regex: "^[a-f0-9]{48}$",
		Algos: []string{
			"Haval-192",
			"Tiger-192",
			"SHA-1(Oracle)",
			"OSX v10.4",
			"OSX v10.5",
			"OSX v10.6",
		},
	},
	{
		Regex: "^[a-f0-9]{51}$",
		Algos: []string{
			"Palshop CMS",
		},
	},
	{
		Regex: "^[a-z0-9]{51}$",
		Algos: []string{
			"CryptoCurrency(PrivateKey)",
		},
	},
	{
		Regex: "^{ssha1}[0-9]{2}\\$[a-z0-9$\\/.]{44}$",
		Algos: []string{
			"AIX(ssha1)",
		},
	},
	{
		Regex: "^0x0100[a-f0-9]{48}$",
		Algos: []string{
			"MSSQL(2005)",
			"MSSQL(2008)",
		},
	},
	{
		Regex: "^(\\$md5,rounds=[0-9]+\\$|\\$md5\\$rounds=[0-9]+\\$|\\$md5\\$)[a-z0-9\\/.]{0,16}(\\$|\\$\\$)[a-z0-9\\/.]{22}$",
		Algos: []string{
			"Sun MD5 Crypt",
		},
	},
	{
		Regex: "^[a-f0-9]{56}$",
		Algos: []string{
			"SHA-224",
			"Haval-224",
			"SHA3-224",
			"Skein-256(224)",
			"Skein-512(224)",
		},
	},
	{
		Regex: "^(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$",
		Algos: []string{
			"Blowfish(OpenBSD)",
			"Woltlab Burning Board 4.x",
			"bcrypt",
		},
	},
	{
		Regex: "^[a-f0-9]{40}:[a-f0-9]{16}$",
		Algos: []string{
			"Android PIN",
		},
	},
	{
		Regex: "^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$",
		Algos: []string{
			"Oracle 11g/12c",
		},
	},
	{
		Regex: "^\\$bcrypt-sha256\\$(2[axy]|2)\\,[0-9]+\\$[a-z0-9\\/.]{22}\\$[a-z0-9\\/.]{31}$",
		Algos: []string{
			"bcrypt(SHA-256)",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:.{3}$",
		Algos: []string{
			"vBulletin < v3.8.5",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:.{30}$",
		Algos: []string{
			"vBulletin \u2265 v3.8.5",
		},
	},
	{
		Regex: "^(\\$snefru\\$)?[a-f0-9]{64}$",
		Algos: []string{
			"Snefru-256",
		},
	},
	{
		Regex: "^[a-f0-9]{64}(:.+)?$",
		Algos: []string{
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
		Regex: "^[a-f0-9]{32}:[a-z0-9]{32}$",
		Algos: []string{
			"Joomla < v2.5.18",
		},
	},
	{
		Regex: "^[a-f-0-9]{32}:[a-f-0-9]{32}$",
		Algos: []string{
			"SAM(LM_Hash:NT_Hash)",
		},
	},
	{
		Regex: "^(\\$chap\\$0\\*)?[a-f0-9]{32}[\\*:][a-f0-9]{32}(:[0-9]{2})?$",
		Algos: []string{
			"MD5(Chap)",
			"iSCSI CHAP Authentication",
		},
	},
	{
		Regex: "^\\$episerver\\$\\*0\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{27,28}$",
		Algos: []string{
			"EPiServer 6.x < v4",
		},
	},
	{
		Regex: "^{ssha256}[0-9]{2}\\$[a-z0-9$\\/.]{60}$",
		Algos: []string{
			"AIX(ssha256)",
		},
	},
	{
		Regex: "^[a-f0-9]{80}$",
		Algos: []string{
			"RIPEMD-320",
		},
	},
	{
		Regex: "^\\$episerver\\$\\*1\\*[a-z0-9\\/=+]+\\*[a-z0-9\\/=+]{42,43}$",
		Algos: []string{
			"EPiServer 6.x \u2265 v4",
		},
	},
	{
		Regex: "^0x0100[a-f0-9]{88}$",
		Algos: []string{
			"MSSQL(2000)",
		},
	},
	{
		Regex: "^[a-f0-9]{96}$",
		Algos: []string{
			"SHA-384",
			"SHA3-384",
			"Skein-512(384)",
			"Skein-1024(384)",
		},
	},
	{
		Regex: "^{SSHA512}[a-z0-9\\/+]{96}$",
		Algos: []string{
			"SSHA-512(Base64)",
			"LDAP(SSHA-512)",
		},
	},
	{
		Regex: "^{ssha512}[0-9]{2}\\$[a-z0-9\\/.]{16,48}\\$[a-z0-9\\/.]{86}$",
		Algos: []string{
			"AIX(ssha512)",
		},
	},
	{
		Regex: "^[a-f0-9]{128}(:.+)?$",
		Algos: []string{
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
		Regex: "^[a-f0-9]{136}$",
		Algos: []string{
			"OSX v10.7",
		},
	},
	{
		Regex: "^0x0200[a-f0-9]{136}$",
		Algos: []string{
			"MSSQL(2012)",
			"MSSQL(2014)",
		},
	},
	{
		Regex: "^\\$ml\\$[0-9]+\\$[a-f0-9]{64}\\$[a-f0-9]{128}$",
		Algos: []string{
			"OSX v10.8",
			"OSX v10.9",
		},
	},
	{
		Regex: "^[a-f0-9]{256}$",
		Algos: []string{
			"Skein-1024",
		},
	},
	{
		Regex: "^grub\\.pbkdf2\\.sha512\\.[0-9]+\\.([a-f0-9]{128,1000}[a-f0-9]{0,1000}[a-f0-9]{0,48}\\.|[0-9]+\\.)?[a-f0-9]{128}$",
		Algos: []string{
			"GRUB 2",
		},
	},
	{
		Regex: "^sha1\\$[a-z0-9]+\\$[a-f0-9]{40}$",
		Algos: []string{
			"Django(SHA-1)",
		},
	},
	{
		Regex: "^[a-f0-9]{49}$",
		Algos: []string{
			"Citrix Netscaler",
		},
	},
	{
		Regex: "^\\$S\\$[a-z0-9\\/.]{52}$",
		Algos: []string{
			"Drupal > v7.x",
		},
	},
	{
		Regex: "^\\$5\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{43}$",
		Algos: []string{
			"SHA-256 Crypt",
		},
	},
	{
		Regex: "^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$",
		Algos: []string{
			"Sybase ASE",
		},
	},
	{
		Regex: "^\\$6\\$(rounds=[0-9]+\\$)?[a-z0-9\\/.]{0,16}\\$[a-z0-9\\/.]{86}$",
		Algos: []string{
			"SHA-512 Crypt",
		},
	},
	{
		Regex: "^\\$sha\\$[a-z0-9]{1,16}\\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$",
		Algos: []string{
			"Minecraft(AuthMe Reloaded)",
		},
	},
	{
		Regex: "^sha256\\$[a-z0-9]+\\$[a-f0-9]{64}$",
		Algos: []string{
			"Django(SHA-256)",
		},
	},
	{
		Regex: "^sha384\\$[a-z0-9]+\\$[a-f0-9]{96}$",
		Algos: []string{
			"Django(SHA-384)",
		},
	},
	{
		Regex: "^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$",
		Algos: []string{
			"Clavister Secure Gateway",
		},
	},
	{
		Regex: "^[a-f0-9]{112}$",
		Algos: []string{
			"Cisco VPN Client(PCF-File)",
		},
	},
	{
		Regex: "^[a-f0-9]{1000}[a-f0-9]{329}$",
		Algos: []string{
			"Microsoft MSTSC(RDP-File)",
		},
	},
	{
		Regex: "^[^\\\\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\\\\/:*?\"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$",
		Algos: []string{
			"NetNTLMv1-VANILLA / NetNTLMv1+ESS",
		},
	},
	{
		Regex: "^([^\\\\\\/:*?\"<>|]{1,20}\\\\)?[^\\\\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\\\\/:*?\"<>|]{1,20}:)?[^\\\\\\/:*?\"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$",
		Algos: []string{
			"NetNTLMv2",
		},
	},
	{
		Regex: "^\\$(krb5pa|mskrb5)\\$([0-9]{2})?\\$.+\\$[a-f0-9]{1,}$",
		Algos: []string{
			"Kerberos 5 AS-REQ Pre-Auth",
		},
	},
	{
		Regex: "^\\$scram\\$[0-9]+\\$[a-z0-9\\/.]{16}\\$sha-1=[a-z0-9\\/.]{27},sha-256=[a-z0-9\\/.]{43},sha-512=[a-z0-9\\/.]{86}$",
		Algos: []string{
			"SCRAM Hash",
		},
	},
	{
		Regex: "^[a-f0-9]{40}:[a-f0-9]{0,32}$",
		Algos: []string{
			"Redmine Project Management Web App",
		},
	},
	{
		Regex: "^(.+)?\\$[a-f0-9]{16}$",
		Algos: []string{
			"SAP CODVN B (BCODE)",
		},
	},
	{
		Regex: "^(.+)?\\$[a-f0-9]{40}$",
		Algos: []string{
			"SAP CODVN F/G (PASSCODE)",
		},
	},
	{
		Regex: "^(.+\\$)?[a-z0-9\\/.+]{30}(:.+)?$",
		Algos: []string{
			"Juniper Netscreen/SSG(ScreenOS)",
		},
	},
	{
		Regex: "^0x[a-f0-9]{60}\\s0x[a-f0-9]{40}$",
		Algos: []string{
			"EPi",
		},
	},
	{
		Regex: "^[a-f0-9]{40}:[^*]{1,25}$",
		Algos: []string{
			"SMF \u2265 v1.1",
		},
	},
	{
		Regex: "^(\\$wbb3\\$\\*1\\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$",
		Algos: []string{
			"Woltlab Burning Board 3.x",
		},
	},
	{
		Regex: "^[a-f0-9]{130}(:[a-f0-9]{40})?$",
		Algos: []string{
			"IPMI2 RAKP HMAC-SHA1",
		},
	},
	{
		Regex: "^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\\.[a-z0-9-.]+$",
		Algos: []string{
			"Lastpass",
		},
	},
	{
		Regex: "^[a-z0-9\\/.]{16}([:$].{1,})?$",
		Algos: []string{
			"Cisco-ASA(MD5)",
		},
	},
	{
		Regex: "^\\$vnc\\$\\*[a-f0-9]{32}\\*[a-f0-9]{32}$",
		Algos: []string{
			"VNC",
		},
	},
	{
		Regex: "^[a-z0-9]{32}(:([a-z0-9-]+\\.)?[a-z0-9-.]+\\.[a-z]{2,7}:.+:[0-9]+)?$",
		Algos: []string{
			"DNSSEC(NSEC3)",
		},
	},
	{
		Regex: "^(user-.+:)?\\$racf\\$\\*.+\\*[a-f0-9]{16}$",
		Algos: []string{
			"RACF",
		},
	},
	{
		Regex: "^\\$3\\$\\$[a-f0-9]{32}$",
		Algos: []string{
			"NTHash(FreeBSD Variant)",
		},
	},
	{
		Regex: "^\\$sha1\\$[0-9]+\\$[a-z0-9\\/.]{0,64}\\$[a-z0-9\\/.]{28}$",
		Algos: []string{
			"SHA-1 Crypt",
		},
	},
	{
		Regex: "^[a-f0-9]{70}$",
		Algos: []string{
			"hMailServer",
		},
	},
	{
		Regex: "^[:\\$][AB][:\\$]([a-f0-9]{1,8}[:\\$])?[a-f0-9]{32}$",
		Algos: []string{
			"MediaWiki",
		},
	},
	{
		Regex: "^[a-f0-9]{140}$",
		Algos: []string{
			"Minecraft(xAuth)",
		},
	},
	{
		Regex: "^\\$pbkdf2(-sha1)?\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{27}$",
		Algos: []string{
			"PBKDF2-SHA1(Generic)",
		},
	},
	{
		Regex: "^\\$pbkdf2-sha256\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{43}$",
		Algos: []string{
			"PBKDF2-SHA256(Generic)",
		},
	},
	{
		Regex: "^\\$pbkdf2-sha512\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{86}$",
		Algos: []string{
			"PBKDF2-SHA512(Generic)",
		},
	},
	{
		Regex: "^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+-]{27}=$",
		Algos: []string{
			"PBKDF2(Cryptacular)",
		},
	},
	{
		Regex: "^\\$p5k2\\$[0-9]+\\$[a-z0-9\\/.]+\\$[a-z0-9\\/.]{32}$",
		Algos: []string{
			"PBKDF2(Dwayne Litzenberger)",
		},
	},
	{
		Regex: "^{FSHP[0123]\\|[0-9]+\\|[0-9]+}[a-z0-9\\/+=]+$",
		Algos: []string{
			"Fairly Secure Hashed Password",
		},
	},
	{
		Regex: "^\\$PHPS\\$.+\\$[a-f0-9]{32}$",
		Algos: []string{
			"PHPS",
		},
	},
	{
		Regex: "^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{80}$",
		Algos: []string{
			"1Password(Agile Keychain)",
		},
	},
	{
		Regex: "^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$",
		Algos: []string{
			"1Password(Cloud Keychain)",
		},
	},
	{
		Regex: "^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$",
		Algos: []string{
			"IKE-PSK MD5",
		},
	},
	{
		Regex: "^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$",
		Algos: []string{
			"IKE-PSK SHA1",
		},
	},
	{
		Regex: "^[a-z0-9\\/+]{27}=$",
		Algos: []string{
			"PeopleSoft",
		},
	},
	{
		Regex: "^crypt\\$[a-f0-9]{5}\\$[a-z0-9\\/.]{13}$",
		Algos: []string{
			"Django(DES Crypt Wrapper)",
		},
	},
	{
		Regex: "^(\\$django\\$\\*1\\*)?pbkdf2_sha256\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{44}$",
		Algos: []string{
			"Django(PBKDF2-HMAC-SHA256)",
		},
	},
	{
		Regex: "^pbkdf2_sha1\\$[0-9]+\\$[a-z0-9]+\\$[a-z0-9\\/+=]{28}$",
		Algos: []string{
			"Django(PBKDF2-HMAC-SHA1)",
		},
	},
	{
		Regex: "^bcrypt(\\$2[axy]|\\$2)\\$[0-9]{2}\\$[a-z0-9\\/.]{53}$",
		Algos: []string{
			"Django(bcrypt)",
		},
	},
	{
		Regex: "^md5\\$[a-f0-9]+\\$[a-f0-9]{32}$",
		Algos: []string{
			"Django(MD5)",
		},
	},
	{
		Regex: "^\\{PKCS5S2\\}[a-z0-9\\/+]{64}$",
		Algos: []string{
			"PBKDF2(Atlassian)",
		},
	},
	{
		Regex: "^md5[a-f0-9]{32}$",
		Algos: []string{
			"PostgreSQL MD5",
		},
	},
	{
		Regex: "^\\([a-z0-9\\/+]{49}\\)$",
		Algos: []string{
			"Lotus Notes/Domino 8",
		},
	},
	{
		Regex: "^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\\/+=]{1,}$",
		Algos: []string{
			"scrypt",
		},
	},
	{
		Regex: "^\\$8\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$",
		Algos: []string{
			"Cisco Type 8",
		},
	},
	{
		Regex: "^\\$9\\$[a-z0-9\\/.]{14}\\$[a-z0-9\\/.]{43}$",
		Algos: []string{
			"Cisco Type 9",
		},
	},
	{
		Regex: "^\\$office\\$\\*2007\\*[0-9]{2}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{40}$",
		Algos: []string{
			"Microsoft Office 2007",
		},
	},
	{
		Regex: "^\\$office\\$\\*2010\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$",
		Algos: []string{
			"Microsoft Office 2010",
		},
	},
	{
		Regex: "^\\$office\\$\\*2013\\*[0-9]{6}\\*[0-9]{3}\\*[0-9]{2}\\*[a-z0-9]{32}\\*[a-z0-9]{32}\\*[a-z0-9]{64}$",
		Algos: []string{
			"Microsoft Office 2013",
		},
	},
	{
		Regex: "^\\$fde\\$[0-9]{2}\\$[a-f0-9]{32}\\$[0-9]{2}\\$[a-f0-9]{32}\\$[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{1000}[a-f0-9]{72}$",
		Algos: []string{
			"Android FDE \u2264 4.3",
		},
	},
	{
		Regex: "^\\$oldoffice\\$[01]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{32}$",
		Algos: []string{
			"Microsoft Office \u2264 2003 (MD5+RC4)",
			"Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #1",
			"Microsoft Office \u2264 2003 (MD5+RC4) collider-mode #2",
		},
	},
	{
		Regex: "^\\$oldoffice\\$[34]\\*[a-f0-9]{32}\\*[a-f0-9]{32}\\*[a-f0-9]{40}$",
		Algos: []string{
			"Microsoft Office \u2264 2003 (SHA1+RC4)",
			"Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #1",
			"Microsoft Office \u2264 2003 (SHA1+RC4) collider-mode #2",
		},
	},
	{
		Regex: "^(\\$radmin2\\$)?[a-f0-9]{32}$",
		Algos: []string{
			"RAdmin v2.x",
		},
	},
	{
		Regex: "^{x-issha,\\s[0-9]{4}}[a-z0-9\\/+=]+$",
		Algos: []string{
			"SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
		},
	},
	{
		Regex: "^\\$cram_md5\\$[a-z0-9\\/+=-]+\\$[a-z0-9\\/+=-]{52}$",
		Algos: []string{
			"CRAM-MD5",
		},
	},
	{
		Regex: "^[a-f0-9]{16}:2:4:[a-f0-9]{32}$",
		Algos: []string{
			"SipHash",
		},
	},
	{
		Regex: "^[a-f0-9]{4,}$",
		Algos: []string{
			"Cisco Type 7",
		},
	},
	{
		Regex: "^[a-z0-9\\/.]{13,}$",
		Algos: []string{
			"BigCrypt",
		},
	},
	{
		Regex: "^(\\$cisco4\\$)?[a-z0-9\\/.]{43}$",
		Algos: []string{
			"Cisco Type 4",
		},
	},
	{
		Regex: "^bcrypt_sha256\\$\\$(2[axy]|2)\\$[0-9]+\\$[a-z0-9\\/.]{53}$",
		Algos: []string{
			"Django(bcrypt-SHA256)",
		},
	},
	{
		Regex: "^\\$postgres\\$.[^\\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$",
		Algos: []string{
			"PostgreSQL Challenge-Response Authentication (MD5)",
		},
	},
	{
		Regex: "^\\$siemens-s7\\$[0-9]{1}\\$[a-f0-9]{40}\\$[a-f0-9]{40}$",
		Algos: []string{
			"Siemens-S7",
		},
	},
	{
		Regex: "^(\\$pst\\$)?[a-f0-9]{8}$",
		Algos: []string{
			"Microsoft Outlook PST",
		},
	},
	{
		Regex: "^sha256[:$][0-9]+[:$][a-z0-9\\/+]+[:$][a-z0-9\\/+]{32,128}$",
		Algos: []string{
			"PBKDF2-HMAC-SHA256(PHP)",
		},
	},
	{
		Regex: "^(\\$dahua\\$)?[a-z0-9]{8}$",
		Algos: []string{
			"Dahua",
		},
	},
	{
		Regex: "^\\$mysqlna\\$[a-f0-9]{40}[:*][a-f0-9]{40}$",
		Algos: []string{
			"MySQL Challenge-Response Authentication (SHA1)",
		},
	},
	{
		Regex: "^\\$pdf\\$[24]\\*[34]\\*128\\*[0-9-]{1,5}\\*1\\*(16|32)\\*[a-f0-9]{32,64}\\*32\\*[a-f0-9]{64}\\*(8|16|32)\\*[a-f0-9]{16,64}$",
		Algos: []string{
			"PDF 1.4 - 1.6 (Acrobat 5 - 8)",
		},
	},
}

// Search will write the found matches into the given channel.
//
// The given channel will be closed at the end of the operation.
func Search(b []byte, ch chan<- string) {
	for _, e := range database {
		re := regexp.MustCompile(e.Regex)

		if re.Match(b) {
			ch <- strings.Join(e.Algos, "\n")
		}
	}

	close(ch)
}
