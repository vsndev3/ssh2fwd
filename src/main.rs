use clap::Parser;
use futures::executor::block_on;
use futures::lock::Mutex;
use log::{debug, error, info, trace, warn};
use ssh2::Session;
use ssh2::Stream;
use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};

#[derive(Parser)]
#[clap(
    version = "1.0",
    about = "Port forwarding via SSH\n\nRun this application \
 to connect to remote SSH server\nand access a different server that is reachable via SSH \
 server to a local port\n\n\
 e.g ./ssh2fwd --sshaddress 10.0.0.1:22 --sshuser username --remote-srv localhost --remote-port 8080 -l 0.0.0.0:8181\
 "
)]
struct Opts {
    /// Address of the SSH server, must be in IP:PORT or DNS:PORT format
    #[clap(short = 's', long)]
    sshaddress: String,
    /// User name to login to SSH server
    #[clap(short = 'u', long, default_value = "invalid_user")]
    sshuser: String,
    /// Remote address that is reachable via SSH server
    #[clap(short = 'r', long, default_value = "localhost")]
    remote_srv: String,
    /// Remote port that is reachable via SSH server
    #[clap(short = 'p', long, default_value = "8080")]
    remote_port: u16,
    /// Local address:port we have to bind for providing connectivity to RemoteAddress:RemotePort
    #[clap(short = 'l', long, default_value = "127.0.0.1:8080")]
    local_srv_address: String,
}

fn get_channels_for_remote_server(
    remote_srv: &str,
    remote_port: u16,
    session: &Session,
    stream_ref: Arc<Mutex<i32>>,
) -> anyhow::Result<(Stream, Stream)> {
    let mut stream_id = block_on(stream_ref.lock());
    info!(
        "Trying to open channel with stream_id {} in {}:{}",
        *stream_id, remote_srv, remote_port
    );

    match session.channel_direct_tcpip(remote_srv, remote_port, Some((remote_srv, remote_port))) {
        Ok(c) => {
            let writer_stream = { c.stream(*stream_id) };
            let reader_stream = { c.stream(*stream_id) };
            info!("stream_id {} opened", *stream_id);
            *stream_id += 1;
            Ok((reader_stream, writer_stream))
        }
        Err(e) => {
            error!(
                "Unable to open channel, error: {}, >> make sure there is server running 
                   at {}:{} which is rechable via the SSH server! <<",
                e, remote_srv, remote_port
            );
            Err(e.into())
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_target(false)
        .format_timestamp(None)
        .init();

    let args = Opts::parse();
    let sshaddr = if args.sshaddress.contains(":") {
        args.sshaddress
    } else {
        args.sshaddress + ":22"
    };
    let sshuser = args.sshuser;
    let remote_srv = args.remote_srv;
    let remote_port = args.remote_port;
    let localsrv = args.local_srv_address;

    info!("Connecting to SSH server at {}", &sshaddr);
    let tcp = TcpStream::connect(&sshaddr).await?;
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;
    info!(
        "Connected to {}!. Now authendicating as user: {}",
        &sshaddr, sshuser
    );

    // Try to authenticate with the first identity in the agent.
    match session.userauth_agent(&sshuser) {
        Ok(_) => {}
        Err(e) => {
            warn!(
                "ssh-agent identity did not help, try eval `ssh-agent` and ssh-add. {}",
                e
            );
        }
    }
    if session.authenticated() != true {
        while session.authenticated() != true {
            let password = rpassword::prompt_password("Enter password: ").unwrap();
            match session.userauth_password(&sshuser, &password) {
                Err(e) => {
                    error!("Failed password authendication. {}", e);
                    sleep(Duration::from_millis(1000)).await;
                }
                Ok(_) => {}
            }
        }
        info!(
            "Logged user {} via password with server {}",
            sshuser, sshaddr
        );
    } else {
        info!("User {} logged in to {}", sshuser, sshaddr);
    }

    let listener = TcpListener::bind(localsrv).await?;

    loop {
        let (socket, info) = listener.accept().await?;
        let handle_session = session.clone();
        let stream = Arc::new(Mutex::new(0));
        let remote_srvc = remote_srv.clone();

        info!("New local connection for tunneling. {:?}", info);
        tokio::spawn(async move {
            let (mut rxchan, mut txchan) = get_channels_for_remote_server(
                &remote_srvc,
                remote_port,
                &handle_session,
                stream.clone(),
            )
            .unwrap();
            let (mut local_rd, mut local_wr) = socket.into_split();

            handle_session.set_timeout(20);

            let t1 = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0; 1024];
                debug!("Running new local read task");
                loop {
                    match block_on(local_rd.read(&mut buf)) {
                        Ok(0) => {
                            warn!("No bytes read from local connection. Closing.");
                            break;
                        }
                        Ok(n) => {
                            trace!("Local connection read {} bytes", n);
                            if txchan.write_all(&buf[..n]).is_err() {
                                error!("Write to ssh channel failure {} bytes. Closing", n);
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                            continue;
                        }
                        Err(e) => {
                            error!("Error on reading from local connection {:?}. Closing", e);
                            break;
                        }
                    }
                }
            });

            let t2 = tokio::task::spawn_blocking(move || {
                let mut buf = vec![0; 1024];
                debug!("Running new remote read task");
                loop {
                    match rxchan.read(&mut buf) {
                        Ok(0) => {
                            warn!("No bytes read from remote channel. Closing");
                            break;
                        }
                        Ok(n) => {
                            trace!("Remote channel read {} bytes", n);
                            if block_on(local_wr.write_all(&buf[..n])).is_err() {
                                error!("Writing to local socket {}. Closing", n);
                                break;
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                            continue;
                        }
                        Err(e) => {
                            error!("Error on writing to remote channel {:?}. Closing.", e);
                            break;
                        }
                    }
                }
            });

            t1.await.unwrap();
            t2.await.unwrap();

            handle_session.set_timeout(3000);
        });
    }
}
