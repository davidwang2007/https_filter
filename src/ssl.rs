use chrono::Local;
use env_logger::Env;
use log::debug;
use std::env;
use std::path::{Path, MAIN_SEPARATOR};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    net::IpAddr,
    path::PathBuf,
    process::{Command, ExitStatus},
    sync::Arc,
};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, BufWriter};
use tokio::sync::Mutex;
use trust_dns_resolver::config;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{
    self,
    client::{ServerCertVerified, ServerCertVerifier},
    ClientConfig, ServerName,
};
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

/// generate tls client config
/// trust any certificates provieded
pub fn mk_tls_client_config(target: &str) -> (Arc<ClientConfig>, ServerName) {
    // let mut root_cert_store = rustls::RootCertStore::empty();
    // root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
    //     OwnedTrustAnchor::from_subject_spki_name_constraints(
    //         ta.subject,
    //         ta.spki,
    //         ta.name_constraints,
    //     )
    // }));
    // let addr: SocketAddr = target.parse().expect("Unable to parse socket address");
    let host = target.split(":").next().unwrap();

    // 我们这里不校验证书, 注意 dependency.feature的设置
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(NoopPkiVerifier::new())
        .with_no_client_auth();
    // 如果想使用校验证书的逻辑，则使用下面两行代替上面
    // .with_root_certificates(root_cert_store)
    // .with_no_client_auth();

    // ServerName就是IpAddress 对应的是 标准库中的 IpAddr, 我们转换一下即可
    let domain = ServerName::try_from(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
        .unwrap();

    (Arc::new(config), domain)
}

struct NoopPkiVerifier {}
impl NoopPkiVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}
impl ServerCertVerifier for NoopPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        debug!("verifying server certificate {:?} {:?}", server_name, now);
        Ok(ServerCertVerified::assertion())
    }
}

/// get ip address from host name string
pub async fn get_ip_addr(host_name: &str) -> IpAddr {
    let cfg = config::ResolverConfig::google();
    let mut ops = config::ResolverOpts::default();
    ops.use_hosts_file = false;
    let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(cfg, ops).unwrap();
    let response = resolver.lookup_ip(host_name).await.unwrap();
    response.iter().next().expect("no address returned")
}

/// generate cert for speicified host_name
pub fn gen_cert_if_needed(work_dir: &str, host_name: &str) -> Result<(String, String), String> {
    let file_key = format!("{work_dir}{MAIN_SEPARATOR}{host_name}.key");
    let file_csr = format!("{work_dir}{MAIN_SEPARATOR}{host_name}.csr");
    let file_cert = format!("{work_dir}{MAIN_SEPARATOR}{host_name}.crt");
    let file_ext = format!("{work_dir}{MAIN_SEPARATOR}http.ext");
    let file_ca_cert = env::var("ROOT_CA_CERT")
        .unwrap_or_else(|_| format!("{work_dir}{MAIN_SEPARATOR}rootCA.crt"));
    let file_ca_key =
        env::var("ROOT_CA_KEY").unwrap_or_else(|_| format!("{work_dir}{MAIN_SEPARATOR}rootCA.key"));

    if Path::new(file_cert.as_str()).exists() {
        debug!(
            "cert file: {} has already exists! Just return",
            file_cert.as_str()
        );
        return Ok((file_cert, file_key));
    }

    {
        debug!("generate ext file: {}", file_ext);
        let mut buf = OpenOptions::new()
            // .create_new(false)
            .write(true)
            .truncate(true)
            .open(file_ext.as_str())
            .unwrap();
        buf.write_all(
            format!(
                "keyUsage = nonRepudiation, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth, clientAuth\nsubjectAltName=@SubjectAlternativeName\n[ SubjectAlternativeName ]\nDNS.1={host_name}"
            )
            .as_bytes()
        ).expect("generate ext file failed!");
    }

    // generate key
    debug!("Generate key file: {}", file_key.as_str());
    let output = Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(file_key.as_str())
        .arg("4096")
        .output()
        .unwrap();
    let status = output.status;
    if !status.success() {
        let line = String::from_utf8(output.stderr.to_vec()).unwrap();
        println!("error: {}", line);
        return Err(String::from("create key file failed!"));
    }

    //generate csr
    debug!("generate csr file: {}", file_csr.as_str());
    let output = Command::new("openssl")
        .arg("req")
        .arg("-new")
        .arg("-key")
        .arg(file_key.as_str())
        .arg("-subj")
        .arg(format!("/CN={host_name}/emailAddress=davidwang2006@aliyun.com/C=US/ST=Ohio/L=Columbus/O=Widgets Inc/OU=Some Unit"))
        .arg("-out")
        .arg(file_csr.as_str())
        .output()
        .unwrap();
    let status = output.status;
    if !status.success() {
        let line = String::from_utf8(output.stderr.to_vec()).unwrap();
        println!("error: {}", line);
        return Err(String::from("create csr file failed!"));
    }
    //generate crt
    debug!(
        "generate cert file: {}, with csr: {}, ca_cert: {}, ca_key: {}, ext: {}",
        file_cert.as_str(),
        file_csr.as_str(),
        file_ca_cert.as_str(),
        file_ca_key.as_str(),
        file_ext.as_str()
    );
    // let output = Command::new("cmd")
    //     .arg("/c")
    // .arg("openssl x509 -req -in d:\\data\\keys\\www.baidu.com.csr -CA d:\\data\\keys\\rootCA.crt -CAkey d:\\data\\keys\\rootCA.key -CAcreateserial -out d:\\data\\keys\\www.baidu.com.crt  -days 720 -sha256 -extfile d:\\data\\keys\\http.ext")
    // .arg(format!("openssl x509 -req -in {file_csr} -CA {file_ca_cert} -CAkey {file_ca_key} -CAcreateserial -out {file_cert}  -days 720 -sha256 -extfile {file_ext}"))
    // 下面的写法一直失败，未找到原因,又奇怪的好了
    let output = Command::new("openssl")
        .arg("x509")
        .arg("-req")
        .arg("-in")
        .arg(file_csr.as_str())
        .arg("-CA")
        .arg(file_ca_cert.as_str())
        .arg("-CAkey")
        .arg(file_ca_key.as_str())
        .arg("-CAcreateserial")
        .arg("-out")
        .arg(file_cert.as_str())
        .arg("-days")
        .arg("720")
        .arg("-sha256")
        .arg("-extfile")
        .arg(file_ext.as_str())
        .output()
        .unwrap();
    let status = output.status;
    if !status.success() {
        let line = String::from_utf8(output.stdout.to_vec()).unwrap();
        println!("stdout: {}", line);
        let line = String::from_utf8(output.stderr.to_vec()).unwrap();
        println!("error: {}", line);
        return Err(String::from("create csr file failed!"));
    }

    Ok((file_cert, file_key))
}

/// copy reader to writer
pub async fn copy<'a, R, W>(
    client_id: u32,
    reader: &'a mut R,
    writer: &'a mut W,
    bytes_counter: Arc<Mutex<u64>>,
    log_writer: Arc<Mutex<BufWriter<File>>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; 1 << 10];
    // local -> remote
    let mut total: u64 = 0;
    let mut n = reader.read(&mut buf).await?;
    total += n as u64;
    shrink(&mut buf[0..n]);
    while n > 0 {
        {
            let mut req_c = bytes_counter.lock().await;
            *req_c += n as u64;
        }

        writer.write_all(&mut buf[..n]).await?;
        writer.flush().await?;

        let title = format!(
            "\n>>[{}] {}\n",
            client_id,
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        {
            let mut log = log_writer.lock().await;
            log.write_all(title.as_bytes()).await?;
            log.write_all(&mut buf[..n]).await?;
            log.flush().await?;
            debug!("write to log: {}", n);
        }
        n = reader.read(&mut buf).await?;
        total += n as u64;
        shrink(&mut buf[0..n]);
        debug!("read {} for next", n);
    }

    return Ok(total);
}

#[test]
fn test_0() {
    let env = Env::default()
        .filter_or("RUST_LOG", "debug")
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
    gen_cert_if_needed("d:\\data\\keys", "ww.baidu.com");
}
