# Nmap

Enumerar usuarios `nmap -p 25 --script smtp-enum-users 10.10.10.10`

```java

```

# Smtp-user-enum

Enumerar usuarios `smtp-user-enum -M VRFY -U usuarios.txt -t 10.10.10.10`

```java

```

# Metasploit

`msfconsole`
`use auxiliary/scanner/smtp/smtp_enum`
`set RHOSTS 10.10.10.10`
`set USER_FILE /path/to/usuarios.txt`
`run`

```java

```

# Swaks

`swaks --to usuario@1.1.1.1 --from test@test.com --server 10.10.10.10`

```java

```
