#!/bin/bash

#hardening version 2.0 by DevOps Appmax!
echo "Criando arquivo de logs"
sudo touch /var/log/log_script.txt ;
log=/var/log/log_script.txt

# Adicionando grupo ssh_users aos usuários
sudo addgroup ssh_users ;
sudo usermod -aG ssh_users root ;
sudo usermod -aG ssh_users ubuntu ;

# Realiza backup do sshd_config

#sudo cp -R /etc/ssh/sshd_config /opt/devops/backup-hardening/

######################################################
echo "Atualizando APT"
sudo apt update ;
echo "Aplicando configurações!"
#2.1.Garantir que a montagem dos sistemas de arquivos freevxfs, jffs2, hfs, hfsplus, squashfs e udf estejam desativadas#


#Para freevxfs#

sudo touch /etc/modprobe.d/freevxfs.conf &&
sudo echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf &&
sudo rmmod freevxfs ;

#Para jffs2#

sudo touch /etc/modprobe.d/jffs2.conf &&
sudo echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf &&
sudo rmmod jffs2 ;

#Para hfs#

sudo touch /etc/modprobe.d/hfs.conf &&
sudo echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf &&
sudo rmmod hfs ;

#Para hfsplus#

sudo touch /etc/modprobe.d/hfsplus.conf &&
sudo echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf &&
sudo rmmod hfsplus ;

#Para squashfs#

sudo touch /etc/modprobe.d/squashfs.conf &&
sudo echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf &&
sudo rmmod squashfs

#Para udf#

sudo touch /etc/modprobe.d/udf.conf &&
sudo echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf &&
sudo rmmod udf ;

#2.3.Garantir que o sticky-bit seja colocado em todos os diretórios que podem ser world-writtable#

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'

#2.4.Desativar o armazenamento USB#

sudo touch /etc/modprobe.d/usb_storage.conf &&
sudo echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf &&
sudo rmmod usb-storage ;

#2.5. Garantir que os comandos sudo usam pty

sudo echo "Defaults use_pty" >> /etc/sudoers ;

#2.6. Garantir a existência do arquivo sudo log

sudo echo "default logfile=/var/log/sudo.log" >> /etc/sudoers ;

#2.7.Garantir a autenticação necessária para o modo usuário único# (Nao se aplica, utilizamos chaves ssh)

#echo "Digite uma senha para o usuário root";
#sudo passwd ;

#2.8. Criar id de usuários únicos para cada administrador de sistema (Nao se aplica, cada pessoa tem seu proprio user)

#2.9.Garantir que o prelink esteja desativado#

sudo prelink -ua ;
sudo apt purge prelink ;

#2.10. Garantir que a mensagem do dia esteja configurada corretamente

sudo mkdir /etc/motd ;
sudo echo "O ACESSO NÃO AUTORIZADO A ESTE DISPOSITIVO É PROIBIDO
Você deve ter permissão explícita e autorizada para acessar ou configurar este dispositivo. Tentativas e ações não autorizadas para acessar ou usar este sistema podem resultar em penalidades civis e/ou criminais. Todas as atividades realizadas neste dispositivo são registradas e monitoradas." >> /etc/motd ;

#2.11. Garantir que o banner de aviso de login remoto esteja configurado corretamente

sudo echo "O ACESSO NÃO AUTORIZADO A ESTE DISPOSITIVO É PROIBIDO
Você deve ter permissão explícita e autorizada para acessar ou configurar este dispositivo. Tentativas e ações não autorizadas para acessar ou usar este sistema podem resultar em penalidades civis e/ou criminais. Todas as atividades realizadas neste dispositivo são registradas e monitoradas." > /etc/issue.net ;

#2.12. Garantir que as permissões no /etc/motd estejam configuradas

sudo chown root:root /etc/motd ;
sudo chmod u-x,go-wx /etc/motd ;

#2.13.Garantir que as permissões no /etc/issue.net estejam configuradas#

chown root:root /etc/issue.net ;
chmod u-x,go-wx /etc/issue.net ;

#2.14.Garantir que atualizações, correções e software de segurança adicional sejam instalados#

sudo apt upgrade -y ;

#2.15.Garantir que a sincronização de tempo esteja em uso#
#instala, starta e habilita o ntp#

sudo apt install ntp -y ;
sudo service ntp start ;
sudo systemctl enable ntp ;

#2.16. Garantir que o ntp está configurado

sudo cat /etc/ntp/ntp.conf ;

#2.17.Garantir que o Avahi Server não esteja habilitado#

sudo systemctl --now disable avahi-daemon ;

#2.18.Garantir que o DHCP Server não esteja habilitado#

sudo systemctl --now disable isc-dhcp-server ;
sudo systemctl --now disable isc-dhcp-server6 ;

#2.19.Garantir que o servidor LDAP não esteja habilitado#

sudo systemctl --now disable slapd ;
sudo systemctl stop slapd;

#2.20.Garantir que o NFS e RPC não estejam habilitados#

sudo systemctl --now disable nfs-server ;
sudo systemctl --now disable rpcbind ;

#2.21.Garantir que o servidor DNS não esteja habilitado#

sudo systemctl --now disable bind9 ;
sudo service bind9 stop ;

#2.22.Garantir que o Samba não seja ativado#

sudo systemctl --now disable smbd ;
sudo service smbd stop ;

#2.23.Garantir que o servidor proxy HTTP não esteja habilitado#

sudo systemctl --now disable squid ;
sudo service squid stop ;

#2.24.Garantir que o servidor SNMP não esteja habilitado#

sudo systemctl --now disable snmpd ;
sudo service snmpd stop ;

#2.25.Garantir que o Servidor NIS não esteja habilitado#

sudo systemctl --now disable nis ;
sudo service nis stop ;

#2.26. Desabilitar IPv6 (Nao se aplica)

#2.27.Garantir que o DCCP esteja desativado#

sudo touch /etc/modprobe.d/dccp.conf &&
sudo echo "install dccp /bin/true" >> /etc/modprobe.d/hfsplus.conf ;

#2.28.Garantir que o SCTP esteja desativado#

sudo touch /etc/modprobe.d/sctp.conf &&
sudo echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf ;

#2.29.Garantir que o RDS esteja desativado#

sudo touch /etc/modprobe.d/rds.conf &&
sudo echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf ;

#2.30.Garantir que o TIPC está desativado#

sudo touch /etc/modprobe.d/tipc.conf &&
sudo echo "install tipc /bin/true" >> /etc/modprobe.d/tipc.conf ;

#2.31.Garantir que o serviço de auditoria (logs) esteja instalado#

sudo apt install auditd audispd-plugins -y ;

#2.32.Garantir que o serviço de auditoria (logs) esteja habilitado#

sudo systemctl --now enable auditd &&
sudo service auditd start ;

#2.37.Garantir que eventos que modificam informações de data e hora sejam coletados#

sudo touch /etc/audit/rules.d/time-change.rules &&
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change -a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" > /etc/audit/rules.d/time-change.rules ;

#2.38. Garantir que os eventos que modificam as informações do usuário/grupo sejam coletados

sudo touch /etc/audit/rules.d/identity.rules ;
echo "-w /etc/passwd -p wa -k identity -w /etc/gshadow -p wa -k identity -w /etc/shadow -p wa -k identity -w" >> /etc/audit/rules.d/identity.rules ;
echo "/etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules ;

#2.39. Garantir que os eventos que modificam o ambiente de rede do sistema sejam coletados

sudo touch /etc/audit/rules.d/system-locale.rules &&
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale -w /etc/issue -p wa -k system-locale -w /etc/issue.net -p wa -k system-locale -w /etc/hosts -p wa -k system-locale -w /etc/network -p wa -k system-locale" > /etc/audit/rules.d/time-change.rules ;

#2.40. Garantir que os eventos que modificam os Controles de Acesso Obrigatórios do sistema sejam coletados

sudo touch /etc/audit/rules.d/MAC-policy.rules &&
echo "-w /etc/apparmor/ -p wa -k MAC-policy -w /etc/apparmor.d/ -p wa -k MAC-policy" > /etc/audit/rules.d/time-change.rules ;

#2.41.Garantir que os eventos de login e logout sejam coletados#

sudo touch /etc/audit/rules.d/logins.rules  &&
echo "-w /var/log/faillog -p wa -k logins -w /var/log/lastlog -p wa -k logins -w /var/log/tallylog -p wa -k logins" > /etc/audit/rules.d/logins.rules ;

#2.42.Garantir que as informações de início de sessão sejam coletadas#

sudo touch /etc/audit/rules.d/session.rules  &&
echo "-w /var/run/utmp -p wa -k session -w /var/log/wtmp -p wa -k logins -w /var/log/btmp -p wa -k logins" > /etc/audit/rules.d/session.rules ;

#2.43.Garantir que as mudanças no escopo de administração do sistema (sudoers) sejam coletadas#

sudo touch /etc/audit/rules.d/scope.rules &&
echo "-w /etc/sudoers -p wa -k escopo -w /etc/sudoers.d/ -p wa -k escopo" > /etc/audit/rules.d/scope.rules ;

#2.44.Garantir que as ações do administrador do sistema (sudolog) sejam coletadas#

sudo touch /etc/audit/rules.d/actions.rules &&
echo "w /var/log/sudo.log -p wa -k actions" > /etc/audit/rules.d/actions.rules;

#2.45.Garantir que a configuração da auditoria seja imutável#

sudo touch /etc/audit/rules.d/99-finalize.rules &&
echo "-e 2" > /etc/audit/rules.d/99-finalize.rules ;

#2.46. Garantir que o rsyslog esteja instalado

sudo apt install rsyslog ;

#2.47. Garantir que o serviço rsyslog esteja habilitado

sudo systemctl --now enable rsyslog ;

#2.48. Garantir que o cron daemon esteja habilitado

sudo systemctl --now enable cron ;

#2.49.Garantir que as permissões no /etc/crontab estejam configuradas#

sudo chown root:root /etc/crontab ;
sudo chmod og-rwx /etc/crontab ;

#2.50.Garantir que as permissões no /etc/cron.hourly estejam configuradas#

sudo chown root:root /etc/cron.hourly ;
sudo chmod og-rwx /etc/cron.hourly ;

#2.51.Garantir que as permissões no /etc/cron.daily sejam configuradas#

sudo chown root:root /etc/cron.daily ;
sudo chmod og-rwx /etc/cron.daily ;

#2.52.Garantir que as permissões no /etc/cron.semanais estejam configuradas#

sudo chown root:root /etc/cron.weekly ;
sudo chmod og-rwx /etc/cron.weekly ;
 
#2.53.Garantir que as permissões no /etc/cron.mensal sejam configuradas#

sudo chown root:root /etc/cron.monthly ;
sudo chmod og-rwx /etc/cron.monthly ;

#2.54.Garantir que as permissões no /etc/cron.d estejam configuradas#

sudo chown root:root /etc/cron.d ;
sudo chmod og-rwx /etc/cron.d ;

#2.55.Garantir que o /etc/cron esteja restrito a usuários autorizados#

#sudo rm -rf /etc/cron.deny ;
sudo touch /etc/cron.allow ;
sudo chown root:root /etc/cron.allow ;
sudo chmod g-wx,o-rwx /etc/cron.allow ;

#2.56.Garantir que as permissões em /etc/ssh/sshd_config estejam configuradas#

sudo chown root:root /etc/ssh/sshd_config ;
sudo chmod og-rwx /etc/ssh/sshd_config ;

#2.57.Garantir que o Protocolo SSH não esteja definido para versão 1#

sudo echo "Protocol 2" >> /etc/ssh/sshd_config ;

#2.58.Garantir que o SSH LogLevel seja apropriado#

sudo echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config ;

#2.59. Garantir que o encaminhamento SSH X11 esteja desativado

sudo sed -i '/X11Forwarding/d' /etc/ssh/sshd_config ; #remove a linha contendo a palavra antes do /d
sudo echo "X11Forwarding no" >> /etc/ssh/sshd_config ;

#2.60. Garantir que o SSH MaxAuthTries esteja configurado para 4 ou menos

sudo echo "MaxAuthTries 4" >> /etc/ssh/sshd_config ;

#2.61. Garantir que os SSH IgnoreRhosts estejam habilitados

sudo echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config ;

#2.62. Garantir que a autenticação baseada no SSH Host esteja desativada

sudo echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config ;

#2.63. Garantir que o login SSH root esteja desativado

sudo echo "PermitRootLogin no" >> /etc/ssh/sshd_config ;

#2.64. Garantir que o SSH PermitEmptyPasswords seja desativado

sudo echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config ;

#2.65. Garantir que o SSH PermitUserAmbiente esteja desativado

sudo echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config ;

#2.66. Garantir que somente cifras fortes sejam utilizadas

sudo echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config ;

#2.67. Garantir que somente algoritmos MAC fortes sejam usados

sudo echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config ;

#2.68. Garantir que somente algoritmos fortes de troca de chaves sejam usados

sudo echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config ;

#2.69. Garantir que o intervalo de tempo ocioso SSH esteja configurado

sudo echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config ;

#2.70. Garantir que o tempo de acesso SSH LoginGraceTime seja ajustado para um minuto ou menos

sudo echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config ;
sudo echo "LoginGraceTime 60" >> /etc/ssh/sshd_config ;

#2.71. Garantir que o acesso SSH seja limitado

sudo echo "AllowGroups ssh_users" >> /etc/ssh/sshd_config ;

#2.72. Garantir que a advertência SSH esteja configurada

sudo echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config ;

#2.73. Garantir que o SSH PAM esteja habilitado

#sudo echo "UsePAM yes" >> /etc/ssh/sshd_config ;

#2.74. Garantir que o SSH AllowTcpForwarding seja desativado

sudo echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config ;

#2.75. Garantir que o SSH MaxStartups esteja configurado

sudo echo "maxstartups 3" >> /etc/ssh/sshd_config ;

#2.76. Garantir que a SSH MaxSessions seja limitada

sudo echo "MaxSessions 3" >> /etc/ssh/sshd_config ;

#2.86.Garantir que o grupo para a conta root seja GID 0#

sudo usermod -g 0 root

#2.87.Garantir que a máscara de usuário padrão seja 027 ou mais restritiva#
sudo mkdir /opt/devops ;
sudo mkdir /opt/devops/backup-hardening ;
sudo cp -R /etc/profile.d/*.* /opt/devops/backup-hardening/
sudo cp -R /etc/bash.bashrc /opt/devops/backup-hardening/
sudo cp -R /etc/profile /opt/devops/backup-hardening/

sudo echo "umask 027" >> /etc/bash.bashrc ;
sudo echo "umask 027" >> /etc/profile ;
sudo echo "umask 027" >> /etc/profile.d/01-locale-fix.sh ;
sudo echo "umask 027" >> /etc/profile.d/Z97-byobu.sh ;
sudo echo "umask 027" >> /etc/profile.d/Z99-cloud-locale-test.sh ;
sudo echo "umask 027" >> /etc/profile.d/Z99-cloudinit-warnings.sh ;
sudo echo "umask 027" >> /etc/profile.d/apps-bin-path.sh ;
sudo echo "umask 027" >> /etc/profile.d/bash_completion.sh ;
sudo echo "umask 027" >> /etc/profile.d/cedilla-portuguese.sh ;
sudo echo "umask 027" >> /etc/profile.d/gawk.sh ;

#2.88.Garantir que as permissões no /etc/passwd estejam configuradas#

sudo chown root:root /etc/passwd ;
sudo chmod 644 /etc/passwd ;

#2.89.Garantir que as permissões no /etc/gshadow- sejam configuradas#

sudo chown root:root /etc/gshadow-  ;
sudo chown root:shadow /etc/gshadow-  ;
sudo chmod o-rwx,g-wx /etc/gshadow- ;

#2.90.Garantir que as permissões no /etc/shadow sejam configuradas#

sudo chmod o-rwx,g-wx /etc/shadow ;
sudo chown root:shadow /etc/shadow ;

#2.91.Garantir que as permissões no /etc/grupo estejam configuradas#

sudo chown root:root /etc/group ;
sudo chmod 644 /etc/group ;

#2.92.Garantir que as permissões em /etc/passwd- sejam configuradas#

sudo chown root:root /etc/passwd- ;
sudo chmod u-x,go-rwx /etc/passwd- ;

#2.93.Garantir que as permissões no /etc/shadow- sejam configuradas#

sudo chown root:shadow /etc/shadow- ;
sudo chmod u-x,go-rwx /etc/shadow- ;

#2.94.Garantir que as permissões no /etc/group- sejam configuradas#

sudo chown root:root /etc/group-  ;
sudo chmod u-x,go-rwx /etc/group- ;

#2.95.Garantir que as permissões no /etc/gshadow sejam configuradas#

sudo chown root:shadow /etc/gshadow ;
sudo chmod o-rwx,g-wx /etc/gshadow ;