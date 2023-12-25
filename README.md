# ssh2fwd
SSH Port forwarding client

Run this application to connect to remote SSH server and access a different server that is reachable via SSH server to a local port

`
e.g ./ssh2fwd --sshaddress 10.0.0.1:22 --sshuser username --remote-srv localhost --remote-port 8080 -l 0.0.0.0:8181
`
# Building from source
A normal rust build with cargo like below:
```
git clone https://github.com/vsndev3/ssh2fwd.git
cd ssh2fwd
cargo build --release

Binary will be available in ssh2fwd/target/ directory
```

# Usage
```
Usage: ssh2fwd.exe [OPTIONS] --sshaddress <SSHADDRESS>

Options:
  -s, --sshaddress <SSHADDRESS>
          Address of the SSH server, must be in IP:PORT or DNS:PORT format
  -u, --sshuser <SSHUSER>
          User name to login to SSH server [default: invalid_user]
  -r, --remote-srv <REMOTE_SRV>
          Remote address that is reachable via SSH server [default: localhost]
  -p, --remote-port <REMOTE_PORT>
          Remote port that is reachable via SSH server [default: 8080]
  -l, --local-srv-address <LOCAL_SRV_ADDRESS>
          Local address:port we have to bind for providing connectivity to RemoteAddress:RemotePort [default: 127.0.0.1:8080]
  -h, --help
          Print help
  -V, --version
          Print version
```

Run with the required arguments and then connect the client application for contacting remote port accessible via SSH server. Kill the application manually once its done