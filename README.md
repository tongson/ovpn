# ovpn
OpenVPN setup script

Only tested on OpenSUSE Tumbleweed

To build requires the pattern: devel_C_C++<br/>
Requires the packages: openvpn openvpn-auth-pam-plugin google-authenticator-libpam easyrsa

Before building edit the top of `bin/ovpn.fnl` with the desired configuration.

Build:

    make
    make install

To add a client certificate:

    ovpn [CLIENT]

List clients:

    ovpn --list

Revoke client:

    ovpn --revoke [CLIENT]

