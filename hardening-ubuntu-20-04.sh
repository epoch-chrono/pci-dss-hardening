#!/bin/bash

#Definindo variaveis

files=(/etc/bash.bashrc \
/etc/profile \
/etc/profile.d/01-locale-fix.sh \
/etc/profile.d/Z97-byobu.sh \
/etc/profile.d/Z99-cloud-locale-test.sh \
/etc/profile.d/Z99-cloudinit-warnings.sh \
/etc/profile.d/apps-bin-path.sh \
/etc/profile.d/bash_completion.sh \
/etc/profile.d/cedilla-portuguese.sh \
/etc/profile.d/gawk.sh)

#hardening version 2.0 by DevOps Appmax!
echo "Criando arquivo de logs"
sudo touch /var/log/log_script.txt
log=/var/log/log_script.txt

# Adicionando grupo ssh_users aos usuários
sudo addgroup ssh_users
sudo usermod -aG ssh_users root
sudo usermod -aG ssh_users ubuntu

# Realiza backup do sshd_config

#sudo cp -R /etc/ssh/sshd_config /opt/devops/backup-hardening/

######################################################
echo "Atualizando APT"
sudo apt update
echo "Aplicando configurações!"

#2.1 - Desativando sistemas de arquivos freevxfs, jffs2, hfs, hfsplus, squashfs e udf
echo "Desativando sistemas de arquivos freevxfs, jffs2, hfs, hfsplus, squashfs e udf..."

sudo modprobe -r vxfs
sudo modprobe -r jffs2
sudo modprobe -r hfs
sudo modprobe -r hfsplus
sudo modprobe -r squashfs
sudo modprobe -r udf

echo "Feito!"

#2.3. Colocando sticky-bit em todos os diretórios world-writtable
echo "Colocando sticky-bit em todos os diretórios world-writtable..."

# Procurando por diretórios world-writtable
for dir in $(find / -type d -perm -0002 -print); do
  # Colocando sticky-bit
  sudo chmod +t "$dir"
done

echo "Feito!"

#2.4.Desativando armazenamento USB
echo "Desativando armazenamento USB..."

# Desabilitando o módulo USB do kernel
sudo echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

# Recarregando configurações do kernel
sudo update-initramfs -u

echo "Feito!"

#2.5. Garantindo que os comandos sudo usam pty
echo "Garantindo que os comandos sudo usam pty..."

# Adicionando a opção "requiretty" no arquivo /etc/sudoers
sudo sed -i '/Defaults\s\+requiretty/s/^#\s*//' /etc/sudoers

echo "Feito!"

#2.6. Garantindo a existência do arquivo de log do sudo
echo "Garantindo a existência do arquivo de log do sudo..."

# Verificando se o arquivo de log existe
if [ ! -f /var/log/sudo.log ]; then
  # Criando o arquivo de log
  sudo touch /var/log/sudo.log
  # Dando permissão de escrita para o grupo adm
  sudo chgrp adm /var/log/sudo.log
  sudo chmod 0640 /var/log/sudo.log
  echo "Arquivo de log criado com sucesso."
else
  echo "Arquivo de log já existe."
fi

echo "Feito!"

#2.7.Garantir a autenticação necessária para o modo usuário único# (Nao se aplica, utilizamos chaves ssh)

#echo "Digite uma senha para o usuário root";
#sudo passwd

#2.8. Criar id de usuários únicos para cada administrador de sistema (Nao se aplica, cada pessoa tem seu proprio user)

#2.9. Garantindo que o prelink esteja desativado
echo "Garantindo que o prelink esteja desativado..."

# Verificando se o prelink está ativo
if [[ $(dpkg-query -W -f='${Status}' prelink 2>/dev/null) == *"installed"* ]]; then
  # Desativando o prelink
  sudo prelink -ua
  echo "Prelink desativado com sucesso."
else
  echo "Prelink já está desativado."
fi

echo "Feito!"

#2.10. Garantir que a mensagem do dia esteja configurada corretamente

if ! sudo ls -la /etc/motd &>/dev/null; then sudo mkdir -v /etc/motd; fi
sudo echo "O ACESSO NÃO AUTORIZADO A ESTE DISPOSITIVO É PROIBIDO
Você deve ter permissão explícita e autorizada para acessar ou configurar este dispositivo. Tentativas e ações não autorizadas para acessar ou usar este sistema podem resultar em penalidades civis e/ou criminais. Todas as atividades realizadas neste dispositivo são registradas e monitoradas." >> /etc/motd

#2.11. Garantir que o banner de aviso de login remoto esteja configurado corretamente

sudo echo "O ACESSO NÃO AUTORIZADO A ESTE DISPOSITIVO É PROIBIDO
Você deve ter permissão explícita e autorizada para acessar ou configurar este dispositivo. Tentativas e ações não autorizadas para acessar ou usar este sistema podem resultar em penalidades civis e/ou criminais. Todas as atividades realizadas neste dispositivo são registradas e monitoradas." > /etc/issue.net

#2.12. Mudando dono e permissões do arquivo /etc/motd
echo "Mudando dono e permissões do arquivo /etc/motd..."

# Mudando dono do arquivo para root:root
sudo chown root:root /etc/motd

# Removendo permissão de execução para o usuário e permissões de escrita para grupo e outros
sudo chmod 644 /etc/motd

echo "Feito!"

#2.13. Mudando dono e permissões do arquivo /etc/issue.net
echo "Mudando dono e permissões do arquivo /etc/issue.net..."

# Mudando dono do arquivo para root:root
sudo chown root:root /etc/issue.net

# Removendo permissão de execução para o usuário e permissões de escrita para grupo e outros
sudo chmod 644 /etc/issue.net

echo "Feito!"

#2.14.Garantir que atualizações, correções e software de segurança adicional sejam instalados#

sudo apt upgrade -y

#2.15 e 2.16 Instalando e configurando o Chrony
echo "Instalando e configurando o Chrony..."

# Instalando o pacote Chrony
sudo apt-get update
sudo apt-get install -y chrony

# Removendo qualquer configuração anterior do Chrony
sudo sed -i '/^server/d' /etc/chrony/chrony.conf

# Adicionando o servidor de tempo no arquivo de configuração do Chrony
sudo bash -c "echo 'server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4' >> /etc/chrony/chrony.conf"

# Reiniciando o serviço Chrony
sudo systemctl restart chrony

# Habilitando o serviço Chrony para iniciar automaticamente no boot
sudo systemctl enable chrony

echo "Feito!"

#2.17 Desabilitando o Avahi Server
echo "Desabilitando o Avahi Server..."
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon

#2.18 Desabilitando o DHCP Server
echo "Desabilitando o DHCP Server..."
sudo systemctl stop isc-dhcp-server
sudo systemctl stop isc-dhcp-server6
sudo systemctl disable isc-dhcp-server
sudo systemctl disable isc-dhcp-server6

#2.19 Desabilitando o servidor LDAP
echo "Desabilitando o servidor LDAP..."
sudo systemctl stop slapd
sudo systemctl disable slapd

echo "Feito!"

#2.20 Desabilitando NFS e RPC
echo "Desabilitando NFS e RPC..."

sudo systemctl stop nfs-kernel-server
sudo systemctl disable nfs-kernel-server
sudo systemctl stop rpcbind
sudo systemctl disable rpcbind

echo "Feito!"

#2.21 Desabilitando o servidor DNS
echo "Desabilitando o servidor DNS..."

sudo systemctl stop bind9
sudo systemctl disable bind9

echo "Feito!"

#2.22.Garantir que o Samba não seja ativado#

sudo systemctl stop smbd
sudo systemctl disable smbd
sudo apt-get remove samba -y
# Verificar se o diretório /etc/samba/ existe antes de removê-lo
if [ -d "/etc/samba/" ]; then
  sudo rm -rf /etc/samba/
fi

#2.23.Garantir que o servidor proxy HTTP não esteja habilitado#

sudo systemctl stop squid
sudo systemctl disable squid
sudo apt-get remove squid -y

# Verificar se o diretório /etc/squid/ existe antes de removê-lo
if [ -d "/etc/squid/" ]; then
  sudo rm -rf /etc/squid/
fi

#2.24.Garantir que o servidor SNMP não esteja habilitado#

sudo systemctl stop snmpd
sudo systemctl disable snmpd
sudo apt-get remove snmpd -y

# Verificar se o diretório /etc/snmp/ existe antes de removê-lo
if [ -d "/etc/snmp/" ]; then
  sudo rm -rf /etc/snmp/
fi

#2.25.Garantir que o Servidor NIS não esteja habilitado

sudo systemctl stop nis
sudo systemctl disable nis
sudo apt-get remove nis -y

# Verificar se o diretório /etc/yp/ existe antes de removê-lo
if [ -d "/etc/yp/" ]; then
  sudo rm -rf /etc/yp/
fi

#2.26. Desabilitar IPv6 (Nao se aplica)

#2.27.Garantir que o DCCP esteja desativado

sudo touch /etc/modprobe.d/dccp.conf &&
sudo echo "install dccp /bin/true" >> /etc/modprobe.d/hfsplus.conf

#2.28.Garantir que o SCTP esteja desativado

sudo touch /etc/modprobe.d/sctp.conf &&
sudo echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf

#2.29.Garantir que o RDS esteja desativado#

sudo touch /etc/modprobe.d/rds.conf &&
sudo echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf

#2.30.Garantir que o TIPC está desativado#

sudo touch /etc/modprobe.d/tipc.conf &&
sudo echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf

#2.31.Garantir que o serviço de auditoria (logs) esteja instalado#

sudo apt install auditd audispd-plugins -y

#2.32.Garantir que o serviço de auditoria (logs) esteja habilitado#

sudo systemctl --now enable auditd &&
sudo service auditd start

#2.37.Garantir que eventos que modificam informações de data e hora sejam coletados#

sudo touch /etc/audit/rules.d/time-change.rules &&
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change -a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/time-change.rules

#2.38. Garantir que os eventos que modificam as informações do usuário/grupo sejam coletados

sudo touch /etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity -w /etc/gshadow -p wa -k identity -w /etc/shadow -p wa -k identity -w" >> /etc/audit/rules.d/identity.rules
echo "/etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules

#2.39. Garantir que os eventos que modificam o ambiente de rede do sistema sejam coletados

sudo touch /etc/audit/rules.d/system-locale.rules &&
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w /etc/issue -p wa -k system-locale -w /etc/issue.net -p wa -k system-locale -w /etc/hosts -p wa -k system-locale -w /etc/network -p wa -k system-locale" > /etc/audit/rules.d/time-change.rules

#2.40. Garantir que os eventos que modificam os Controles de Acesso Obrigatórios do sistema sejam coletados

sudo touch /etc/audit/rules.d/MAC-policy.rules &&
echo "-w /etc/apparmor/ -p wa -k MAC-policy -w /etc/apparmor.d/ -p wa -k MAC-policy" > /etc/audit/rules.d/time-change.rules

#2.41.Garantir que os eventos de login e logout sejam coletados#

sudo touch /etc/audit/rules.d/logins.rules  &&
echo "-w /var/log/faillog -p wa -k logins -w /var/log/lastlog -p wa -k logins -w /var/log/tallylog -p wa -k logins" > /etc/audit/rules.d/logins.rules

#2.42.Garantir que as informações de início de sessão sejam coletadas#

sudo touch /etc/audit/rules.d/session.rules  &&
echo "-w /var/run/utmp -p wa -k session -w /var/log/wtmp -p wa -k logins -w /var/log/btmp -p wa -k logins" > /etc/audit/rules.d/session.rules

#2.43.Garantir que as mudanças no escopo de administração do sistema (sudoers) sejam coletadas#

sudo touch /etc/audit/rules.d/scope.rules &&
echo "-w /etc/sudoers -p wa -k escopo -w /etc/sudoers.d/ -p wa -k escopo" > /etc/audit/rules.d/scope.rules

#2.44.Garantir que as ações do administrador do sistema (sudolog) sejam coletadas#

sudo touch /etc/audit/rules.d/actions.rules &&
echo "w /var/log/sudo.log -p wa -k actions" > /etc/audit/rules.d/actions.rules;

#2.45.Garantir que a configuração da auditoria seja imutável#

sudo touch /etc/audit/rules.d/99-finalize.rules &&
echo "-e 2" > /etc/audit/rules.d/99-finalize.rules

#2.46. Garantir que o rsyslog esteja instalado

sudo apt install rsyslog

#2.47. Garantir que o serviço rsyslog esteja habilitado

sudo systemctl --now enable rsyslog

#2.48. Garantir que o cron daemon esteja habilitado

sudo systemctl --now enable cron

#2.49.Garantir que as permissões no /etc/crontab estejam configuradas#

sudo chown root:root /etc/crontab
sudo chmod og-rwx /etc/crontab

#2.50.Garantir que as permissões no /etc/cron.hourly estejam configuradas#

sudo chown root:root /etc/cron.hourly
sudo chmod og-rwx /etc/cron.hourly

#2.51.Garantir que as permissões no /etc/cron.daily sejam configuradas#

sudo chown root:root /etc/cron.daily
sudo chmod og-rwx /etc/cron.daily

#2.52.Garantir que as permissões no /etc/cron.semanais estejam configuradas#

sudo chown root:root /etc/cron.weekly
sudo chmod og-rwx /etc/cron.weekly
 
#2.53.Garantir que as permissões no /etc/cron.mensal sejam configuradas#

sudo chown root:root /etc/cron.monthly
sudo chmod og-rwx /etc/cron.monthly

#2.54.Garantir que as permissões no /etc/cron.d estejam configuradas#

sudo chown root:root /etc/cron.d
sudo chmod og-rwx /etc/cron.d

#2.55.Garantir que o /etc/cron esteja restrito a usuários autorizados#

#sudo rm -rf /etc/cron.deny
sudo touch /etc/cron.allow
sudo chown root:root /etc/cron.allow
sudo chmod g-wx,o-rwx /etc/cron.allow

#2.56.Garantir que as permissões em /etc/ssh/sshd_config estejam configuradas#

sudo chown root:root /etc/ssh/sshd_config
sudo chmod og-rwx /etc/ssh/sshd_config

#2.57.Garantir que o Protocolo SSH não esteja definido para versão 1#

sudo echo "Protocol 2" >> /etc/ssh/sshd_config

#2.58.Garantir que o SSH LogLevel seja apropriado#

sudo echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

#2.59. Garantir que o encaminhamento SSH X11 esteja desativado

sudo sed -i '/X11Forwarding/d' /etc/ssh/sshd_config #remove a linha contendo a palavra antes do /d
sudo echo "X11Forwarding no" >> /etc/ssh/sshd_config

#2.60. Garantir que o SSH MaxAuthTries esteja configurado para 4 ou menos

sudo echo "MaxAuthTries 4" >> /etc/ssh/sshd_config

#2.61. Garantir que os SSH IgnoreRhosts estejam habilitados

sudo echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

#2.62. Garantir que a autenticação baseada no SSH Host esteja desativada

sudo echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config

#2.63. Garantir que o login SSH root esteja desativado

sudo echo "PermitRootLogin no" >> /etc/ssh/sshd_config

#2.64. Garantir que o SSH PermitEmptyPasswords seja desativado

sudo echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config

#2.65. Garantir que o SSH PermitUserAmbiente esteja desativado

sudo echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config

#2.66. Garantir que somente cifras fortes sejam utilizadas

sudo echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config

#2.67. Garantir que somente algoritmos MAC fortes sejam usados

sudo echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config

#2.68. Garantir que somente algoritmos fortes de troca de chaves sejam usados

sudo echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

#2.69. Garantir que o intervalo de tempo ocioso SSH esteja configurado

sudo echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config

#2.70. Garantir que o tempo de acesso SSH LoginGraceTime seja ajustado para um minuto ou menos

sudo echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
sudo echo "LoginGraceTime 60" >> /etc/ssh/sshd_config

#2.71. Garantir que o acesso SSH seja limitado

sudo echo "AllowGroups ssh_users" >> /etc/ssh/sshd_config

#2.72. Garantir que a advertência SSH esteja configurada

sudo echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

#2.73. Garantir que o SSH PAM esteja habilitado

#sudo echo "UsePAM yes" >> /etc/ssh/sshd_config

#2.74. Garantir que o SSH AllowTcpForwarding seja desativado

sudo echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config

#2.75. Garantir que o SSH MaxStartups esteja configurado

sudo echo "maxstartups 3" >> /etc/ssh/sshd_config

#2.76. Garantir que a SSH MaxSessions seja limitada

sudo echo "MaxSessions 3" >> /etc/ssh/sshd_config

#2.86.Garantir que o grupo para a conta root seja GID 0#

sudo usermod -g 0 root

#2.87.Garantir que a máscara de usuário padrão seja 027 ou mais restritiva#

if ! sudo ls -la /opt/devops &>/dev/null; then sudo mkdir -v /opt/devops; fi
if ! sudo ls -la /opt/devops/backup-hardening &>/dev/null; then sudo mkdir -v /opt/devops/backup-hardening; fi
sudo cp -R /etc/profile.d/*.* /opt/devops/backup-hardening/
sudo cp -R /etc/bash.bashrc /opt/devops/backup-hardening/
sudo cp -R /etc/profile /opt/devops/backup-hardening/

    #Defina os arquivos na viriável files no inicio do script
for file in "${files[@]}"; do
    sudo echo "umask 027" >> $file
done

#2.88.Garantir que as permissões no /etc/passwd estejam configuradas#

sudo chown root:root /etc/passwd & sudo chmod 644 /etc/passwd

#2.89.Garantir que as permissões no /etc/gshadow- sejam configuradas#

sudo chown root:root /etc/gshadow- & sudo chown root:shadow /etc/gshadow- & sudo chmod o-rwx,g-wx /etc/gshadow-

#2.90.Garantir que as permissões no /etc/shadow sejam configuradas#

sudo chmod o-rwx,g-wx /etc/shadow
sudo chown root:shadow /etc/shadow

#2.91.Garantir que as permissões no /etc/grupo estejam configuradas#

sudo chown root:root /etc/group
sudo chmod 644 /etc/group

#2.92.Garantir que as permissões em /etc/passwd- sejam configuradas#

sudo chown root:root /etc/passwd-
sudo chmod u-x,go-rwx /etc/passwd-

#2.93.Garantir que as permissões no /etc/shadow- sejam configuradas#

sudo chown root:shadow /etc/shadow-
sudo chmod u-x,go-rwx /etc/shadow-

#2.94.Garantir que as permissões no /etc/group- sejam configuradas#

sudo chown root:root /etc/group-
sudo chmod u-x,go-rwx /etc/group-

#2.95.Garantir que as permissões no /etc/gshadow sejam configuradas#

sudo chown root:shadow /etc/gshadow
sudo chmod o-rwx,g-wx /etc/gshadow