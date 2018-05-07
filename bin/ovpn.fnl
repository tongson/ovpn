(local CFG {
       "SERVER-CN" ""
       "SERVER-NAME" ""
       "CERT-VALIDITY" ""
       "IP" ""
       "PORT" ""
       "CIDR" ""
       "NAMESERVER" ""
       "DH-KEY-SIZE" ""
       "RSA-KEY-SIZE" ""})
(local EASYRSA-DIR "/etc/openvpn/easy-rsa")
(var SERVER-CONF "dev tun\
port ${PORT}\
proto udp\
user nobody\
group nogroup\
persist-key\
persist-tun\
keepalive 10 120\
topology subnet\
server ${NETWORK}\
ifconfig-pool-persist ipp.txt\
push \"dhcp-option DNS ${NAMESERVER}\"\
push \"redirect-gateway def1 block-local\"\
crl-verify crl.pem\
ca ca.crt\
cert ${SERVER-NAME}.crt\
key ${SERVER-NAME}.key\
tls-auth tls-auth.key 0\
dh dh.pem\
auth SHA256\
reneg-sec 0\
cipher AES-128-CBC\
tls-server\
tls-version-min 1.2\
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256\
status openvpn.log\
verb 3\
plugin openvpn-plugin-auth-pam.so \"openvpn login COMMONNAME password PASSWORD\"\
")
(var CLIENT-CONF "remote ${IP} ${PORT}\
proto udp\
dev tun\
resolv-retry infinite\
nobind\
persist-key\
persist-tun\
remote-cert-tls server\
verify-x509-name ${SERVER-NAME} name\
auth SHA256\
auth-user-pass\
reneg-sec 0\
auth-nocache\
cipher AES-128-CBC\
pull\
tls-client\
tls-cipher TLS-DHE-RSA-WITH-AES-128-GCM-SHA256\
tls-version-min 1.2\
verb 3\
<ca>\
${CA}</ca>\
<cert>\
${CERT}</cert>\
<key>\
${KEY}</key>\
key-direction 1\
<tls-auth>\
${TLS-AUTH}</tls-auth>\
")
(var PAM "auth required pam_google_authenticator.so secret=/etc/openvpn/users/${USER}/.google_authenticator user=0 forward_pass allowed_perm=0400\
account required pam_permit.so")

(local lib (require "lib"))
(local (file exec table fmt string func) (values (. lib "file")
                                                 (. lib "exec")
                                                 (. lib "table")
                                                 (. lib "fmt")
                                                 (. lib "string")
                                                 (. lib "func")))
(local (os ipairs cmd echo) (values os ipairs exec.cmd fmt.print))
(local try (func.try fmt.panic))
(local arg arg)
(try (rawget arg 1) "[!] Missing command line argument\n")
(local CLIENT (tostring (. arg 1)))
(global _ENV nil)

(local easyrsa (exec.ctx "easyrsa"))
(tset easyrsa "cwd" EASYRSA-DIR)
(tset easyrsa "env" [(.. "EASYRSA_PKI=" EASYRSA-DIR "/pki")
                    (.. "EASYRSA_KEY_SIZE=" (. CFG "RSA-KEY-SIZE"))
                    (.. "EASYRSA_REQ_CN=" (. CFG "SERVER-CN"))])

;; Setup OpenVPN server
(when (not (file.stat "/etc/openvpn/ca.crt"))
  (cmd.mkdir ["-p" "/etc/openvpn/users"])
  (file.write "/etc/pam.d/openvpn" PAM)
  (set SERVER-CONF (string.gsub SERVER-CONF "%${[%s]-([^}%G]+)[%s]-}" CFG))
  (file.write "/etc/openvpn/server.conf" SERVER-CONF)
  (cmd.rm ["-r" "-f" EASYRSA-DIR])
  (cmd.mkdir [EASYRSA-DIR])

  (try (easyrsa "init-pki") "[!] init-pki failed\n")

  (try (easyrsa "--batch" "build-ca" "nopass") "[!] build-ca failed\n")

  (try (cmd.openssl ["dhparam" "-out" (.. EASYRSA-DIR "/pki/dh.pem") (. CFG "DH-KEY-SIZE")])
       "[!] openssl dhparam failed\n")

  (try (easyrsa "build-server-full" (. CFG "SERVER-NAME") "nopass")
       "[!] build-server-full failed\n")

  (tset easyrsa "env" [(.. "EASYRSA_CRL_DAYS=" (. CFG "CERT-VALIDITY"))])
  (try (easyrsa "gen-crl") "[!] gen-crl failed\n")

  (try (cmd.openvpn ["--genkey" "--secret" "/etc/openvpn/tls-auth.key"])
       "[!] tls-auth.key generation failed\n")

  (local cp (exec.ctx "cp"))
  (tset cp "cwd" EASYRSA-DIR)
  (try (cp "pki/ca.crt"
           "pki/private/ca.key"
           "pki/dh.pem"
           (.. "pki/issued/" (. CFG "SERVER-NAME") ".crt")
           (.. "pki/private/" (. CFG "SERVER-NAME") ".key")
           "pki/crl.pem"
           "/etc/openvpn")
       "[!] copying files failed\n")

  (local fw (exec.ctx "firewall-cmd"))
  (try (fw "--zone=public" (.. "--add-port=" (. CFG "PORT") "/udp") "--permanent")
       "[!] Enabling OpenVPN port failed\n")
  (try (fw "--zone=trusted" (.. "--add-source=" (. CFG "CIDR")) "--permanent")
       "[!] Enabling OpenVPN subnet failed\n")
  (try (fw "--zone=public" "--add-port=22/tcp" "--permanent")
       "[!] Enabling SSH port failed\n")
  (try (fw "--zone=public" "--add-masquerade" "--permanent")
       "[!] Enabling MASQUERADING failed\n"))

(when (= "--list" (. arg 1))
  (echo (file.read (.. EASYRSA-DIR "/pki/index.txt")))
  (os.exit 0))
(when (= "--revoke" (. arg 1))
  (cmd.rm ["-f" (.. "/etc/openvpn/users/" (. arg 2) "/.google_authenticator")])
  (cmd.rmdir [(.. "/etc/openvpn/users/" (. arg 2))])
  (try (easyrsa "--batch" "revoke" (. arg 2)) "[!] revoke failed\n")
  (try (easyrsa "gen-crl") "[!] gen-crl failed\n")
  (cmd.rm ["-f" (.. EASYRSA-DIR "/pki/reqs/" (. arg 2) ".req")])
  (cmd.rm ["-f" (.. EASYRSA-DIR "/pki/private/" (. arg 2) ".key")])
  (cmd.rm ["-f" (.. EASYRSA-DIR "/pki/issued/" (. arg 2) ".crt")])
  (cmd.rm ["-f" "/etc/openvpn/crl.pem"])
  (cmd.cp ["/etc/openvpn/easy-rsa/pki/crl.pem" "/etc/openvpn/crl.pem"])
  (cmd.chmod ["644" "/etc/openvpn/crl.pem"])
  (file.write (.. EASYRSA-DIR "/pki/index.txt") (table.concat (table.filter (file.to_array (.. EASYRSA-DIR "/pki/index.txt")) (.. "CN=" (. arg 2)) true) "\n"))
  (os.exit 0))

(try (easyrsa "build-client-full" CLIENT "nopass") "[!] build-client-full failed\n")
(tset CFG "CA" (file.read (.. EASYRSA-DIR "/pki/ca.crt")))
(tset CFG "CERT" (file.read (.. EASYRSA-DIR "/pki/issued/" CLIENT ".crt")))
(tset CFG "KEY" (file.read (.. EASYRSA-DIR "/pki/private/" CLIENT ".key")))
(tset CFG "TLS-AUTH" (file.read "/etc/openvpn/tls-auth.key"))
(set CLIENT-CONF (string.gsub CLIENT-CONF "%${[%s]-([^}%G]+)[%s]-}" CFG))
(file.write (.. CLIENT ".ovpn") CLIENT-CONF)
(cmd.mkdir [(.. "/etc/openvpn/users/" CLIENT)])
(local gauth (exec.ctx "google-authenticator"))
(tset gauth "stdout" (.. CLIENT ".auth"))
(try (gauth "--time-based"
            "--disallow-reuse"
            "--force"
            "--rate-limit=3"
            "--rate-time=30"
            "--window-size=17"
            (.. "--issuer=" (. CFG "SERVER-NAME"))
            (.. "--label=" CLIENT)
            (.. "--secret=/etc/openvpn/users/" CLIENT "/.google_authenticator"))
     "[!] google-authenticator failed\n")
