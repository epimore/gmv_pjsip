use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base::dashmap::DashMap;
use base::tokio::io::{AsyncReadExt, AsyncWriteExt};
use base::tokio::net::{TcpListener as TokioTcpListener, TcpStream, UdpSocket as TokioUdpSocket};
use base::tokio::sync::{mpsc, watch};

use crate::error::{internal_error, Result};
use crate::runtime::{SipRuntimeSockets, SipTransmit};
use crate::transport::SipTransportProtocol;

const UDP_BUFFER_SIZE: usize = 65_535;

pub(crate) enum RuntimeIoCommand {
    Receive {
        association_id: u64,
        protocol: SipTransportProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        data: Vec<u8>,
    },
    CompleteSend {
        send_id: u64,
        result: std::result::Result<usize, i32>,
    },
    TransportClosed {
        association_id: u64,
        protocol: SipTransportProtocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        status: i32,
    },
}

pub(crate) struct SocketIoRuntime {
    shutdown: watch::Sender<bool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SocketIoRuntime {
    pub(crate) fn start(
        sockets: SipRuntimeSockets,
        transmits: mpsc::Receiver<SipTransmit>,
        commands: std::sync::mpsc::SyncSender<RuntimeIoCommand>,
    ) -> Result<Self> {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let thread = thread::Builder::new()
            .name("gmv-pjsip-io".into())
            .spawn(move || {
                let runtime = match base::tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        base::log::error!("start SIP socket runtime failed: {err}");
                        return;
                    }
                };
                runtime.block_on(run_io(sockets, transmits, commands, shutdown_rx));
            })
            .map_err(|err| internal_error(format!("spawn SIP socket IO task failed: {err}")))?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
        })
    }
}

impl Drop for SocketIoRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run_io(
    sockets: SipRuntimeSockets,
    mut transmits: mpsc::Receiver<SipTransmit>,
    commands: std::sync::mpsc::SyncSender<RuntimeIoCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let writers = Arc::new(DashMap::new());
    let next_association_id = Arc::new(AtomicU64::new(1));

    let udp = match sockets.udp {
        Some(socket) => match prepare_udp_socket(socket) {
            Ok(socket) => Some(socket),
            Err(err) => {
                base::log::warn!("prepare SIP UDP socket failed: {err}");
                None
            }
        },
        None => None,
    };
    if let Some(socket) = udp.clone() {
        base::tokio::spawn(read_udp(socket, commands.clone(), shutdown.clone()));
    }

    if let Some(listener) = sockets.tcp {
        match prepare_tcp_listener(listener) {
            Ok(listener) => {
                base::tokio::spawn(accept_tcp(
                    listener,
                    commands.clone(),
                    writers.clone(),
                    next_association_id.clone(),
                    shutdown.clone(),
                ));
            }
            Err(err) => {
                base::log::warn!("prepare SIP TCP listener failed: {err}");
            }
        }
    }

    if sockets.tls.is_some() {
        base::log::warn!(
            "SIP TLS listener was provided, but production certificate loading is not configured"
        );
    }

    loop {
        base::tokio::select! {
            Some(transmit) = transmits.recv() => {
                write_transmit(transmit, udp.as_ref(), &writers, &commands).await;
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

fn prepare_udp_socket(socket: UdpSocket) -> Result<Arc<TokioUdpSocket>> {
    socket
        .set_nonblocking(true)
        .map_err(|err| internal_error(format!("set UDP socket nonblocking failed: {err}")))?;
    TokioUdpSocket::from_std(socket)
        .map(Arc::new)
        .map_err(|err| internal_error(format!("adopt UDP socket failed: {err}")))
}

fn prepare_tcp_listener(listener: TcpListener) -> Result<TokioTcpListener> {
    listener
        .set_nonblocking(true)
        .map_err(|err| internal_error(format!("set TCP listener nonblocking failed: {err}")))?;
    TokioTcpListener::from_std(listener)
        .map_err(|err| internal_error(format!("adopt TCP listener failed: {err}")))
}

async fn read_udp(
    socket: Arc<TokioUdpSocket>,
    commands: std::sync::mpsc::SyncSender<RuntimeIoCommand>,
    mut shutdown: watch::Receiver<bool>,
) {
    let local_addr = match socket.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            base::log::warn!("read SIP UDP local address failed: {err}");
            return;
        }
    };
    let mut buffer = vec![0; UDP_BUFFER_SIZE];
    loop {
        base::tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                match received {
                    Ok((len, remote_addr)) if len > 0 => {
                        let data = buffer[..len].to_vec();
                        log_complete_sip_packet(
                            SipTransportProtocol::Udp,
                            0,
                            local_addr,
                            remote_addr,
                            &data,
                        );
                        let _ = commands.try_send(RuntimeIoCommand::Receive {
                            association_id: 0,
                            protocol: SipTransportProtocol::Udp,
                            local_addr,
                            remote_addr,
                            data,
                        });
                    }
                    Ok(_) => {}
                    Err(err) => {
                        base::log::warn!("read SIP UDP packet failed: {err}");
                        base::tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn accept_tcp(
    listener: TokioTcpListener,
    commands: std::sync::mpsc::SyncSender<RuntimeIoCommand>,
    writers: Arc<DashMap<u64, mpsc::Sender<Vec<u8>>>>,
    next_association_id: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        base::tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        let association_id = next_association_id.fetch_add(1, Ordering::Relaxed);
                        base::tokio::spawn(handle_tcp_stream(
                            association_id,
                            stream,
                            remote_addr,
                            commands.clone(),
                            writers.clone(),
                        ));
                    }
                    Err(err) => {
                        base::log::warn!("accept SIP TCP connection failed: {err}");
                        base::tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn handle_tcp_stream(
    association_id: u64,
    stream: TcpStream,
    remote_addr: SocketAddr,
    commands: std::sync::mpsc::SyncSender<RuntimeIoCommand>,
    writers: Arc<DashMap<u64, mpsc::Sender<Vec<u8>>>>,
) {
    let local_addr = match stream.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            base::log::warn!("read SIP TCP local address failed: {err}");
            return;
        }
    };
    let (mut reader, mut writer) = stream.into_split();
    let (writer_tx, mut writer_rx) = mpsc::channel::<Vec<u8>>(128);
    writers.insert(association_id, writer_tx);

    let writer_commands = commands.clone();
    base::tokio::spawn(async move {
        while let Some(data) = writer_rx.recv().await {
            if writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let mut buffer = Vec::with_capacity(8192);
    let mut chunk = [0; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(len) => {
                buffer.extend_from_slice(&chunk[..len]);
                while let Some(message) = next_sip_message(&mut buffer) {
                    log_complete_sip_packet(
                        SipTransportProtocol::Tcp,
                        association_id,
                        local_addr,
                        remote_addr,
                        &message,
                    );
                    let _ = commands.try_send(RuntimeIoCommand::Receive {
                        association_id,
                        protocol: SipTransportProtocol::Tcp,
                        local_addr,
                        remote_addr,
                        data: message,
                    });
                }
            }
            Err(err) => {
                base::log::warn!(
                    "read SIP TCP connection failed: association_id={association_id}, err={err}"
                );
                break;
            }
        }
    }
    writers.remove(&association_id);
    let _ = writer_commands.try_send(RuntimeIoCommand::TransportClosed {
        association_id,
        protocol: SipTransportProtocol::Tcp,
        local_addr,
        remote_addr,
        status: 1,
    });
}

async fn write_transmit(
    transmit: SipTransmit,
    udp: Option<&Arc<TokioUdpSocket>>,
    writers: &DashMap<u64, mpsc::Sender<Vec<u8>>>,
    commands: &std::sync::mpsc::SyncSender<RuntimeIoCommand>,
) {
    log_outgoing_sip_packet(&transmit);
    let result = match transmit.protocol {
        SipTransportProtocol::Udp => match udp {
            Some(socket) => socket
                .send_to(&transmit.data, transmit.remote_addr)
                .await
                .map_err(|_| 1),
            None => Err(1),
        },
        SipTransportProtocol::Tcp | SipTransportProtocol::Tls => {
            match writers.get(&transmit.association_id) {
                Some(writer) => writer
                    .try_send(transmit.data.clone())
                    .map(|()| transmit.data.len())
                    .map_err(|_| 1),
                None => Err(1),
            }
        }
    };
    let _ = commands.try_send(RuntimeIoCommand::CompleteSend {
        send_id: transmit.send_id,
        result,
    });
}

fn next_sip_message(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n")?;
    let content_length = content_length(&buffer[..header_end]).unwrap_or(0);
    let message_len = header_end + 4 + content_length;
    if buffer.len() < message_len {
        return None;
    }
    Some(buffer.drain(..message_len).collect())
}

fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("Content-Length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn log_complete_sip_packet(
    protocol: SipTransportProtocol,
    association_id: u64,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    data: &[u8],
) {
    base::log::debug!(
        "\nread : [protocol={} association={} local={} remote={} bytes={}]\n{}",
        protocol.as_sip_token(),
        association_id,
        local_addr,
        remote_addr,
        data.len(),
        escape_payload(data)
    );
}

fn log_outgoing_sip_packet(transmit: &SipTransmit) {
    base::log::debug!(
        "\nwrite : [protocol={} association={} local={} remote={} bytes={}]\n{}",
        transmit.protocol.as_sip_token(),
        transmit.association_id,
        transmit.local_addr,
        transmit.remote_addr,
        transmit.data.len(),
        escape_payload(&transmit.data)
    );
}

fn escape_payload(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        // .replace('\\', "\\\\")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
