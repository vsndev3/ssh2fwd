use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::{debug, error, info, trace, warn};
use mio::net::TcpStream as MioTcpStream;
use mio::{Events, Interest, Poll, Token, Waker};
use ssh2::{Channel, ErrorCode, ExtendedData, Session};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream as StdTcpStream};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

const LIBSSH2_ERROR_EAGAIN: i32 = -37;

const BUF_SIZE: usize = 32 * 1024;
const MAX_PENDING: usize = 1024 * 1024;

const TOKEN_SESSION: Token = Token(0);
const TOKEN_WAKE: Token = Token(1);
const FIRST_LOCAL_TOKEN: usize = 2;

#[derive(Parser, Clone)]
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
    /// Timeout for SSH session operations in milliseconds
    #[clap(short = 't', long, default_value = "3000")]
    timeout_ms: u64,
    /// Number of times to retry connecting to the SSH server
    #[clap(long, default_value = "5")]
    connect_retries: u32,
    /// Delay in milliseconds between connection retries
    #[clap(long, default_value = "2000")]
    connect_retry_delay_ms: u64,
    /// Interval in seconds for sending SSH keepalive messages (0 to disable)
    #[clap(long, default_value = "30")]
    keepalive_interval_secs: u32,
    /// Drop a forwarded connection after this many idle seconds (0 to disable)
    #[clap(long, default_value = "0")]
    idle_timeout_secs: u64,
}

fn ssh_would_block(e: &ssh2::Error) -> bool {
    e.code() == ErrorCode::Session(LIBSSH2_ERROR_EAGAIN)
}

#[cfg(unix)]
type SessionFd = std::os::unix::io::RawFd;

#[cfg(not(unix))]
type SessionFd = ();

fn register_session(
    poll: &Poll,
    fd: &SessionFd,
    interest: Option<Interest>,
    registered: &mut bool,
) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut source = mio::unix::SourceFd(fd);
        match (interest, *registered) {
            (Some(i), true) => poll.registry().reregister(&mut source, TOKEN_SESSION, i),
            (Some(i), false) => {
                *registered = true;
                poll.registry().register(&mut source, TOKEN_SESSION, i)
            }
            (None, true) => {
                *registered = false;
                poll.registry().deregister(&mut source)
            }
            (None, false) => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (poll, fd, interest, registered);
        Ok(())
    }
}

fn io_would_block(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

struct Pending {
    data: Vec<u8>,
    pos: usize,
}

impl Pending {
    fn new() -> Self {
        Pending {
            data: Vec::new(),
            pos: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    fn len(&self) -> usize {
        self.data.len() - self.pos
    }

    fn has_room(&self) -> bool {
        self.free() >= BUF_SIZE
    }

    fn free(&self) -> usize {
        MAX_PENDING.saturating_sub(self.len())
    }

    fn push(&mut self, src: &[u8]) {
        self.data.extend_from_slice(src);
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos == self.data.len() {
            self.data.clear();
            self.pos = 0;
        } else if self.pos >= BUF_SIZE {
            self.data.drain(..self.pos);
            self.pos = 0;
        }
    }
}

struct Forward {
    local: MioTcpStream,
    chan: Channel,
    to_local: Pending,
    to_remote: Pending,
    interest: Option<Interest>,
    local_eof: bool,
    remote_eof: bool,
    eof_sent: bool,
    local_write_closed: bool,
    activity: Instant,
}

impl Forward {
    fn wants_read(&self) -> bool {
        !self.remote_eof && self.to_local.has_room()
    }

    /// True while there is still something that has to reach the SSH channel,
    /// including a half-sent EOF that libssh2 could not flush yet.
    fn wants_write(&self) -> bool {
        self.to_remote.len() > 0 || (self.local_eof && !self.eof_sent)
    }

    fn finished(&self) -> bool {
        self.remote_eof && self.to_local.len() == 0 && self.to_remote.len() == 0
    }
}

/// Channel opening has to run in blocking mode: libssh2 only exposes a
/// resumption handle internally, so a non-blocking `channel_direct_tcpip`
/// that returns `EAGAIN` leaks a half-open channel on every retry. The ssh2
/// crate gives us no way to finish one, so we let libssh2 drive the exchange
/// to completion (bounded by `timeout_ms`) and only use non-blocking mode for
/// the data pump.
fn open_channel(session: &Session, host: &str, port: u16) -> Result<Channel> {
    session.set_blocking(true);
    let result = session
        .channel_direct_tcpip(host, port, Some((host, port)))
        .map_err(anyhow::Error::from)
        .map(|mut chan| {
            let _ = chan.handle_extended_data(ExtendedData::Ignore);
            chan
        });
    session.set_blocking(false);

    match result {
        Ok(chan) => {
            trace!("SSH channel to {}:{} opened", host, port);
            Ok(chan)
        }
        Err(e) => {
            error!(
                "Unable to open channel, error: {}, >> make sure there is server running \
                   at {}:{} which is reachable via the SSH server! <<",
                e, host, port
            );
            Err(e)
        }
    }
}

fn establish_session(opts: &Opts, addr: &str) -> Result<Session> {
    let retries = opts.connect_retries.max(1);
    let delay = Duration::from_millis(opts.connect_retry_delay_ms);
    let mut last: Option<anyhow::Error> = None;

    for attempt in 1..=retries {
        match StdTcpStream::connect(addr) {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                let mut session = Session::new()?;
                session.set_tcp_stream(tcp);
                session.set_timeout(opts.timeout_ms as u32);
                match session.handshake() {
                    Ok(()) => {
                        return authenticate(session, &opts.sshuser, opts.keepalive_interval_secs)
                    }
                    Err(e) => {
                        warn!(
                            "Attempt {}/{}: SSH handshake failed: {}",
                            attempt, retries, e
                        );
                        last = Some(e.into());
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Attempt {}/{}: Failed to connect to {}: {}",
                    attempt, retries, addr, e
                );
                last = Some(e.into());
            }
        }
        if attempt < retries {
            std::thread::sleep(delay);
        }
    }

    Err(last.unwrap_or_else(|| anyhow!("Failed to connect to {}", addr)))
}

/// Keepalives must be enabled only once the connection is fully established.
/// libssh2 emits them from its internal wait path and `keepalive_last_sent`
/// starts at 0, so enabling them earlier makes it send a GLOBAL_REQUEST before
/// NEWKEYS. Servers abort that with "Unable to exchange encryption keys".
fn authenticate(session: Session, user: &str, keepalive_secs: u32) -> Result<Session> {
    if let Err(e) = session.userauth_agent(user) {
        warn!(
            "ssh-agent identity did not help, try eval `ssh-agent` and ssh-add. {}",
            e
        );
    }

    if session.authenticated() {
        info!("User {} logged in", user);
        session.set_keepalive(true, keepalive_secs);
        return Ok(session);
    }

    loop {
        let password =
            rpassword::prompt_password("Enter password: ").context("Failed to read password")?;
        match session.userauth_password(user, &password) {
            Ok(_) => break,
            Err(e) => {
                error!("Failed password authentication. {}", e);
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }
    info!("User {} logged in via password", user);
    session.set_keepalive(true, keepalive_secs);
    Ok(session)
}

/// libssh2's `set_blocking` only flips an internal flag and leaves the socket
/// itself blocking. The relay drives libssh2 from a poll() loop and therefore
/// needs real `O_NONBLOCK` on the fd, otherwise every read/write blocks the
/// relay thread instead of returning `WouldBlock`.
fn make_socket_nonblocking(session: &Session) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = session.as_raw_fd();
        // SAFETY: `fd` is owned by the session and remains open for this call.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("Failed to set O_NONBLOCK");
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = session;
        Ok(())
    }
}

struct Conns {
    map: HashMap<usize, Forward>,
    free: Vec<usize>,
    next: usize,
}

impl Conns {
    fn new() -> Self {
        Conns {
            map: HashMap::new(),
            free: Vec::new(),
            next: FIRST_LOCAL_TOKEN,
        }
    }

    fn take_slot(&mut self) -> usize {
        match self.free.pop() {
            Some(s) => s,
            None => {
                let s = self.next;
                self.next += 1;
                s
            }
        }
    }
}

fn admit(
    poll: &Poll,
    session: &Session,
    host: &str,
    port: u16,
    local: StdTcpStream,
    conns: &mut Conns,
) {
    let chan = match open_channel(session, host, port) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut local = MioTcpStream::from_std(local);
    let slot = conns.take_slot();
    let interest = Interest::READABLE;
    if let Err(e) = poll.registry().register(&mut local, Token(slot), interest) {
        error!("Failed to register local socket with poll: {}", e);
        return;
    }

    conns.map.insert(
        slot,
        Forward {
            local,
            chan,
            to_local: Pending::new(),
            to_remote: Pending::new(),
            interest: Some(interest),
            local_eof: false,
            remote_eof: false,
            eof_sent: false,
            local_write_closed: false,
            activity: Instant::now(),
        },
    );
}

fn relay(
    mut poll: Poll,
    waker: Arc<Waker>,
    session: Session,
    rx: Receiver<StdTcpStream>,
    host: String,
    port: u16,
    idle_timeout: Option<Duration>,
) -> Result<()> {
    session.set_blocking(false);
    make_socket_nonblocking(&session)?;

    #[cfg(unix)]
    let session_fd: SessionFd = {
        use std::os::unix::io::AsRawFd;
        session.as_raw_fd()
    };
    #[cfg(not(unix))]
    let session_fd: SessionFd = ();

    let mut session_registered = false;
    register_session(
        &poll,
        &session_fd,
        Some(Interest::READABLE),
        &mut session_registered,
    )
    .context("Failed to register SSH socket with poll")?;

    let mut session_interest = Some(Interest::READABLE);
    let mut events = Events::with_capacity(1024);
    let mut buf = vec![0u8; BUF_SIZE];
    let mut conns = Conns::new();
    let mut rx_open = true;
    let mut session_readable = true;
    let mut session_writable = true;

    loop {
        while rx_open {
            match rx.try_recv() {
                Ok(local) => {
                    trace!("admitting local connection (conns={})", conns.map.len());
                    if let Err(e) = local.set_nonblocking(true) {
                        error!("Failed to set local socket non-blocking: {}", e);
                        continue;
                    }
                    admit(&poll, &session, &host, port, local, &mut conns);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    rx_open = false;
                    let _ = waker.wake();
                    break;
                }
            }
        }

        let mut moved = 0usize;

        if session_readable {
            for f in conns.map.values_mut() {
                while f.wants_read() {
                    match f.chan.read(&mut buf) {
                        Ok(0) => {
                            debug!("SSH channel reached EOF");
                            f.remote_eof = true;
                            break;
                        }
                        Ok(n) => {
                            trace!("SSH channel read {} bytes", n);
                            f.to_local.push(&buf[..n]);
                            moved += n;
                        }
                        Err(ref e) if io_would_block(e) => break,
                        Err(e) => {
                            debug!("Error reading from SSH channel: {}", e);
                            f.remote_eof = true;
                            break;
                        }
                    }
                }
            }
        }

        let has_outbound = conns.map.values().any(|f| f.wants_write());
        if session_writable && has_outbound {
            for f in conns.map.values_mut() {
                while f.to_remote.len() > 0 {
                    match f.chan.write(f.to_remote.bytes()) {
                        Ok(0) => break,
                        Ok(n) => {
                            trace!("Wrote {} bytes to SSH channel", n);
                            f.to_remote.consume(n);
                            moved += n;
                        }
                        Err(ref e) if io_would_block(e) => break,
                        Err(e) => {
                            debug!("Error writing to SSH channel: {}", e);
                            let left = f.to_remote.len();
                            f.to_remote.consume(left);
                            break;
                        }
                    }
                }
            }
        }

        for f in conns.map.values_mut() {
            if f.to_local.len() > 0 {
                match f.local.write(f.to_local.bytes()) {
                    Ok(0) => {}
                    Ok(n) => {
                        trace!("Wrote {} bytes to local socket", n);
                        f.to_local.consume(n);
                        f.activity = Instant::now();
                    }
                    Err(ref e) if io_would_block(e) => {}
                    Err(e) => {
                        debug!("Error writing to local socket: {}", e);
                        f.local_eof = true;
                    }
                }
            }

            if !f.local_eof && f.to_remote.has_room() {
                match f.local.read(&mut buf) {
                    Ok(0) => {
                        debug!("Local connection closed");
                        f.local_eof = true;
                        moved += 1;
                    }
                    Ok(n) => {
                        trace!("Local connection read {} bytes", n);
                        f.to_remote.push(&buf[..n]);
                        f.activity = Instant::now();
                    }
                    Err(ref e) if io_would_block(e) => {}
                    Err(e) => {
                        debug!("Error reading from local socket: {}", e);
                        f.local_eof = true;
                    }
                }
            }
        }

        for f in conns.map.values_mut() {
            if f.local_eof && !f.eof_sent && f.to_remote.len() == 0 {
                match f.chan.send_eof() {
                    Ok(()) => {
                        f.eof_sent = true;
                        moved += 1;
                    }
                    Err(ref e) if ssh_would_block(e) => {}
                    Err(e) => {
                        debug!("Error sending EOF on SSH channel: {}", e);
                        f.eof_sent = true;
                    }
                }
            }
            if f.remote_eof && !f.local_write_closed && f.to_local.len() == 0 {
                let _ = f.local.shutdown(Shutdown::Write);
                f.local_write_closed = true;
                moved += 1;
            }
        }

        let mut reap: Vec<usize> = conns
            .map
            .iter()
            .filter(|(_, f)| f.finished())
            .map(|(slot, _)| *slot)
            .collect();
        if let Some(limit) = idle_timeout {
            let now = Instant::now();
            reap.extend(
                conns
                    .map
                    .iter()
                    .filter(|(_, f)| now.duration_since(f.activity) > limit)
                    .map(|(slot, _)| *slot),
            );
        }
        reap.sort_unstable();
        reap.dedup();
        for slot in reap {
            if let Some(mut f) = conns.map.remove(&slot) {
                let _ = poll.registry().deregister(&mut f.local);
                let _ = f.chan.close();
            }
            conns.free.push(slot);
            moved += 1;
        }

        let mut next_session_interest = None;
        if conns.map.values().any(|f| f.wants_read()) {
            next_session_interest = Some(Interest::READABLE);
        }
        if conns.map.values().any(|f| f.wants_write()) {
            next_session_interest =
                Some(next_session_interest.unwrap_or(Interest::READABLE) | Interest::WRITABLE);
        }
        if next_session_interest != session_interest {
            register_session(
                &poll,
                &session_fd,
                next_session_interest,
                &mut session_registered,
            )?;
            session_interest = next_session_interest;
        }

        for (slot, f) in conns.map.iter_mut() {
            let mut interest = None;
            if !f.local_eof && f.to_remote.has_room() {
                interest = Some(Interest::READABLE);
            }
            if f.to_local.len() > 0 {
                interest = Some(interest.unwrap_or(Interest::READABLE) | Interest::WRITABLE);
            }
            if interest != f.interest {
                match (interest, f.interest) {
                    (Some(i), Some(_)) => {
                        poll.registry().reregister(&mut f.local, Token(*slot), i)?
                    }
                    (Some(i), None) => poll.registry().register(&mut f.local, Token(*slot), i)?,
                    (None, Some(_)) => poll.registry().deregister(&mut f.local)?,
                    (None, None) => {}
                }
                f.interest = interest;
            }
        }

        if !rx_open && conns.map.is_empty() {
            info!("Relay loop finished");
            return Ok(());
        }

        #[cfg(not(unix))]
        let idle_poll_cap = Some(Duration::from_millis(20));
        #[cfg(unix)]
        let idle_poll_cap: Option<Duration> = None;

        let timeout = if moved > 0 {
            Some(Duration::ZERO)
        } else {
            idle_poll_cap
        };

        poll.poll(&mut events, timeout)?;

        session_readable = false;
        session_writable = false;
        for ev in events.iter() {
            if ev.token() == TOKEN_SESSION {
                session_readable |= ev.is_readable() || ev.is_read_closed();
                session_writable |= ev.is_writable() || ev.is_write_closed();
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .format_target(false)
        .format_timestamp(None)
        .init();

    let args = Opts::parse();
    let sshaddr = if args.sshaddress.contains(':') {
        args.sshaddress.clone()
    } else {
        format!("{}:22", args.sshaddress)
    };
    let localsrv = args.local_srv_address.clone();
    let remote_srv = args.remote_srv.clone();
    let remote_port = args.remote_port;
    let idle_timeout =
        (args.idle_timeout_secs > 0).then(|| Duration::from_secs(args.idle_timeout_secs));

    info!("Connecting to SSH server at {}", &sshaddr);
    let session = tokio::task::spawn_blocking({
        let opts = args.clone();
        let addr = sshaddr.clone();
        move || establish_session(&opts, &addr)
    })
    .await
    .context("SSH session task panicked")??;

    info!(
        "Connected to {}!. Now authendicating as user: {}",
        &sshaddr, args.sshuser
    );

    let listener = TcpListener::bind(&localsrv)
        .await
        .with_context(|| format!("Failed to bind local listener on {}", localsrv))?;
    info!("Local listener ready on {}", localsrv);

    let poll = mio::Poll::new().context("Failed to create poll instance")?;
    let waker = std::sync::Arc::new(
        mio::Waker::new(poll.registry(), TOKEN_WAKE).context("Failed to create waker")?,
    );
    let (tx, rx) = mpsc::channel::<StdTcpStream>();
    let relay_handle = std::thread::Builder::new()
        .name("ssh2fwd-relay".into())
        .spawn({
            let waker = waker.clone();
            move || {
                relay(
                    poll,
                    waker,
                    session,
                    rx,
                    remote_srv,
                    remote_port,
                    idle_timeout,
                )
            }
        })
        .context("Failed to spawn relay thread")?;

    loop {
        let (socket, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to accept local connection: {}", e);
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = socket.set_nodelay(true);
        info!("New local connection for tunneling. {:?}", peer);
        let local = match socket.into_std() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to convert local socket: {}", e);
                continue;
            }
        };
        if tx.send(local).is_err() {
            error!("Relay thread stopped, shutting down");
            break;
        }
        if waker.wake().is_err() {
            error!("Failed to wake relay thread");
            break;
        }
    }

    match relay_handle.join() {
        Ok(Ok(())) => info!("Relay thread stopped cleanly"),
        Ok(Err(e)) => error!("Relay thread failed: {:?}", e),
        Err(_) => error!("Relay thread panicked"),
    }
    Ok(())
}
