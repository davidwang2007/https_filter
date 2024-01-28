use chrono::prelude::*;
use clap::Parser;
use env_logger::Env;
use log::{debug, info};
use rand::distributions::uniform::SampleBorrow;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::borrow::BorrowMut;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::ops::{self, Index};
use std::path::PathBuf;
use std::sync::Arc;
use std::{io::Write, path::Path};
use tokio::fs::OpenOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::{TlsAcceptor, TlsConnector};
mod ssl;

/// define arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)] // read from Cargo.toml
pub struct HtArgs {
    /// local listening port
    // #[arg(short, long)]
    // port: u32,
    //debug flag, default_value_t or action can omitted
    /// verbose debug info
    #[arg(short, long)]
    debug: bool,
    /// remote https server address
    #[arg(short, long)]
    target: String,
    #[arg(long, default_value_t = String::from("D:\\data\\keys"))]
    dir: String,
    // #[arg(short, long)]
    // cert: PathBuf,
    // #[arg(short, long)]
    // key: PathBuf,
    #[arg(short, long)]
    log: PathBuf,
}
fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

/// remove Accept-Encoding: gzip, deflate, br
/// headers from array buff
fn shrink(buff: &mut [u8]) -> usize {
    let len = buff.len();
    if len < 20 {
        return len;
    }

    let anchor = b"Accept-Encoding: ";
    let anchor_len = anchor.len();

    let mut idx_start = 0;
    let mut idx_end = 0;

    'outer: for i in 0..len {
        let c0 = buff[i];
        if i + anchor_len > len {
            return len;
        }
        for j in 0..anchor_len {
            // 不匹配直接跳过
            if buff[i + j] != anchor[j] {
                continue 'outer;
            }
        }
        // 走到这一步，即已判定i 为 anchor的起始位置
        // 接下来找\r\n 符号
        for k in i + anchor_len..len {
            if k == len - 1 {
                return len;
            }
            if buff[k] == b'\r' && buff[k + 1] == b'\n' {
                idx_start = i;
                idx_end = k + 1;
                break 'outer;
            }
        }
    }
    // 只留 br
    debug!("Found Accept-Encoding: {} -> {}", idx_start, idx_end);
    let idx_br = idx_start + anchor_len;
    for i in idx_br..idx_end - 1 {
        let c = match i - idx_br {
            0 => b'b',
            1 => b'r',
            2 => b',',
            3 => b'*',
            4 => b',',
            _ => b' ',
        };
        buff[i] = c;
    }
    return len;
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let arg = Arc::new(HtArgs::parse());
    let level = if arg.debug { "debug" } else { "info" };
    let env = Env::default()
        .filter_or("RUST_LOG", level)
        .write_style_or("RUST_LOG_STYLE", "always");

    env_logger::builder()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} - {}: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .parse_env(env)
        .init();

    // let target = arg.target;
    // let ip_port: SocketAddr = target.parse().expect("unable to parse socket address");
    let target = arg.target.split(":").collect::<Vec<&str>>();
    let (host, port) = (
        target.get(0).map(ops::Deref::deref).unwrap(),
        target
            .get(1)
            .map_or("443", ops::Deref::deref)
            .parse::<u16>()
            .unwrap(),
    );
    let (cert, key) = ssl::gen_cert_if_needed(&arg.dir, host).unwrap();

    // not needed
    // let addr = format!("0.0.0.0:{}", port)
    //     .to_socket_addrs()
    //     .unwrap()
    //     .next()
    //     .unwrap();

    // TEST
    let mut reader = BufReader::new(File::open(key)?);
    // for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
    //     match item.unwrap() {
    //         Item::X509Certificate(cert) => println!("certificate {:?}", cert),
    //         Item::RSAKey(key) => println!("rsa pkcs1 key {:?}", key),
    //         Item::PKCS8Key(key) => println!("pkcs8 key {:?}", key),
    //         Item::ECKey(key) => println!("sec1 ec key {:?}", key),
    //         _ => println!("unhandled item"),
    //     }
    // }
    let mut k = pkcs8_private_keys(&mut reader).unwrap();
    // println!("key vec length: {:?}", k.remove(0));
    let pk = PrivateKey(k.remove(0));

    // END

    let certs = load_certs(&PathBuf::from(cert.as_str()))?;
    // let mut keys = load_keys(&arg.key).unwrap();
    // info!("key file is {:?}, keys length is {}", arg.key, keys.len());
    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        // .with_single_cert(certs, keys.remove(0))
        .with_single_cert(certs, pk)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    let log = BufWriter::new(OpenOptions::new().append(true).open(&arg.log).await?);
    let log = Arc::new(tokio::sync::Mutex::new(log));

    //get ip by host
    let ip_v4 = ssl::get_ip_addr(host).await;
    info!("Got ip {} by {}", ip_v4, host);

    info!("listen @port {}", port);
    let active = Arc::new(Mutex::new(0u32));
    let total = Arc::new(Mutex::new(0u32));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let active_counter = Arc::clone(&active);
        let total_counter = Arc::clone(&total);
        {
            let mut c = active_counter.lock().await;
            *c += 1;

            let mut c = total_counter.lock().await;
            *c += 1
        }
        let client_id = { *total_counter.lock().await };
        let active = { *active_counter.lock().await };

        info!("Got client - [{}/{}]: {}", client_id, active, peer_addr);

        let acceptor = acceptor.clone();

        let log = Arc::clone(&log);
        let arg = Arc::clone(&arg);

        let fut = async move {
            let stream = acceptor.accept(stream).await?;
            // ECHO MODE
            // let (mut reader, mut writer) = split(stream);
            // let n = copy(&mut reader, &mut writer).await?;
            // writer.flush().await?;
            // info!("Echo: {} - {}", peer_addr, n);
            // ECHO END

            // HTTP TEST MODE
            // let mut output = sink();
            // let mut stdout = tokio::io::stdout();
            // stream
            //     .write_all(
            //         &b"HTTP/1.0 200 ok\r\n\
            //         Connection: close\r\n\
            //         Content-length: 12\r\n\
            //         \r\n\
            //         Hello world!"[..],
            //     )
            //     .await?;
            // stream.shutdown().await?;
            //consume all left data
            // copy(&mut stream, &mut output).await?;
            // OR copy to standard output
            // copy(&mut stream, &mut stdout).await?;

            // BIDIRECTION
            // let mut buf = [0u8; 512];

            // let mut n = stream.read(&mut buf).await?;
            // while n > 0 {
            //     info!("write to log: {}", n);
            //     let mut log = log.lock().await;
            //     log.write_all(&mut buf[..n]).await?;
            //     log.flush().await?;
            //     info!("write to stdout: {}", n);
            //     stdout.write_all(&mut buf[..n]).await?;
            //     n = stream.read(&mut buf).await?;
            // }
            // println!("bye: {}", peer_addr);
            // HTTP END

            // REAL MODE
            // dial remote
            let tcp = TcpStream::connect(format!("{}:{}", ip_v4, port)).await?;
            debug!("dial remote {:?} succeed!", tcp.peer_addr());
            let (config, host) = ssl::mk_tls_client_config(&arg.target);
            let connector = TlsConnector::from(config);
            let target_stream = connector.connect(host, tcp).await.unwrap();

            let (mut local_r, mut local_w) = tokio::io::split(stream);
            let (mut remote_r, mut remote_w) = tokio::io::split(target_stream);

            let req_c = Arc::new(Mutex::new(0u64));
            let resp_c = Arc::new(Mutex::new(0u64));

            let rt = tokio::select! {
                rt = ssl::copy(client_id, &mut local_r, &mut remote_w, Arc::clone(&req_c), Arc::clone(&log)) => {rt}
                rt = ssl::copy(client_id, &mut remote_r, &mut local_w, Arc::clone(&resp_c), Arc::clone(&log)) => {rt}
            };

            // let rt = tokio::io::copy_bidirectional(&mut stream, &mut tls_stream).await?;
            // debug!("copy bidirectional {} {}", rt.0, rt.1);
            // 因为要写出日志
            // REAL END

            // client disconnected

            {
                let mut c = active_counter.lock().await;
                *c -= 1;
                info!(
                    "client - [{}/{}]: {} disconnected. [r={}/w={}]",
                    client_id,
                    *c,
                    peer_addr,
                    req_c.lock().await,
                    resp_c.lock().await
                );
            }

            // Ok(()) as io::Result<()>
            return rt;
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}
