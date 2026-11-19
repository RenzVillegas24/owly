//! The sender driver: `/Discover` a receiver, then `/Ask` and `/Upload` on
//! one fresh TLS connection (HTTP-1), running a
//! [`proto::sender::Transfer`](crate::proto::sender::Transfer).
//!
//! The `/Ask` goes out from metadata alone; the archive is compressed into a
//! temporary file while the receiver prompts, so a large file does not delay
//! the prompt. The upload still carries a `Content-Length` like Finder's
//! (UP-1a), which is why the body is spooled rather than streamed.

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::net::SocketAddrV6;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use flate2::Compression;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::tls::{self, Identity};
use crate::proto::archive::compress::{Compressor, DVZIP_PIECE, Encoder};
use crate::proto::archive::cpio::{self, Entry};
use crate::proto::archive::extract::RelPath;
use crate::proto::mdns::{SUPPORTS_DVZIP, SUPPORTS_MIXED_TYPES, SUPPORTS_PIPELINING};
use crate::proto::messages::{AskFile, Offer};
use crate::proto::sender::{
    self, Action, Config, Outcome, Receiver, ResponseReader, Transfer, UploadMode,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// A write the receiver doesn't take in this long fails the transfer, so a
/// receiver that stops reading can't hold the sender forever (SEC-10).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// What to send.
#[derive(Debug, Clone)]
pub enum Payload {
    Files(Vec<PathBuf>),
    Urls(Vec<String>),
}

/// Upload progress, in bytes of the compressed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    pub sent: u64,
    pub total: u64,
}

/// What a transfer reports while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The receiver accepted the `/Ask`. A failure after this one is the
    /// upload's.
    Accepted,
    Progress(Progress),
}

pub struct Sender {
    config: Config,
    connector: TlsConnector,
}

impl Sender {
    pub fn new(config: Config) -> io::Result<Self> {
        Self::with_client_identity(config, None)
    }

    /// A sender that presents a client certificate, as Apple senders do
    /// (TLS-3). For tests.
    #[doc(hidden)]
    pub fn with_client_identity(config: Config, identity: Option<&Identity>) -> io::Result<Self> {
        Ok(Sender {
            config,
            connector: TlsConnector::from(tls::client_config(identity)?),
        })
    }

    async fn connect(&self, addr: SocketAddrV6) -> io::Result<TlsStream<TcpStream>> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(tls::server_name(), stream),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    }

    /// `/Discover` on a connection of its own (DISCOVERING in §8.1).
    /// `None` if the receiver doesn't want to be listed (DISC-1).
    pub async fn discover(&self, addr: SocketAddrV6) -> io::Result<Option<Receiver>> {
        let mut tls = self.connect(addr).await?;
        let response = timeout(DISCOVER_TIMEOUT, async {
            tls.write_all(&sender::discover_request()).await?;
            tls.flush().await?;
            read_response(&mut tls).await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let _ = tls.shutdown().await;
        Ok(sender::parse_discover_response(&response))
    }

    /// Asks the receiver at `addr` to take `payload`, and uploads it if it
    /// does. `receiver_flags` is its TXT `flags`, or `0` if they aren't
    /// known, and decides between DVZip and gzip (UP-1b).
    pub async fn send(
        &self,
        addr: SocketAddrV6,
        payload: &Payload,
        receiver_flags: u32,
        events: Option<mpsc::UnboundedSender<Event>>,
    ) -> io::Result<Outcome> {
        self.send_inner(addr, payload, receiver_flags, events, None)
            .await
    }

    /// Like [`Sender::send`], but aborts the transfer when `cancel` becomes
    /// `true`. Cancellation closes the TCP connection abortively so a receiver
    /// stops reading immediately instead of waiting for its idle timeout.
    pub async fn send_with_cancel(
        &self,
        addr: SocketAddrV6,
        payload: &Payload,
        receiver_flags: u32,
        events: Option<mpsc::UnboundedSender<Event>>,
        cancel: watch::Receiver<bool>,
    ) -> io::Result<Outcome> {
        self.send_inner(
            addr,
            payload,
            receiver_flags,
            events,
            Some(cancel),
        )
        .await
    }

    async fn send_inner(
        &self,
        addr: SocketAddrV6,
        payload: &Payload,
        receiver_flags: u32,
        events: Option<mpsc::UnboundedSender<Event>>,
        mut cancel: Option<watch::Receiver<bool>>,
    ) -> io::Result<Outcome> {
        let compressor = compressor(receiver_flags);
        // The offer is metadata only, so the ask can go out at once. The body
        // is compressed in the background; the upload waits for it only after
        // the receiver has accepted.
        let (offer, mut pending, mut stream) = match payload {
            Payload::Urls(urls) => (Offer::Urls(urls.clone()), None, None),
            Payload::Files(paths) => {
                let offer = offer(paths)?;
                let plan = match self.config.upload {
                    UploadMode::Auto if offer_bytes(&offer) >= STORED_BODY_MIN => BodyPlan::Stored,
                    UploadMode::Auto => BodyPlan::Spool,
                    UploadMode::Stream => BodyPlan::Stored,
                    UploadMode::Spool => BodyPlan::Spool,
                    UploadMode::TypeAware if all_compressed(paths) => BodyPlan::Stored,
                    UploadMode::TypeAware => BodyPlan::Spool,
                    UploadMode::Chunked => BodyPlan::Chunked,
                };
                match plan {
                    BodyPlan::Stored => {
                        let cpio = cpio_len(paths)?;
                        let len = stored_body_len(compressor, cpio);
                        let reader = spawn_stored_body(paths.clone(), compressor)?;
                        (offer, None, Some((reader, len)))
                    }
                    BodyPlan::Spool => {
                        let paths = paths.clone();
                        let handle = tokio::task::spawn_blocking(move || {
                            compress(&paths, compressor, Compression::fast())
                        });
                        (offer, Some(handle), None)
                    }
                    BodyPlan::Chunked => {
                        let reader = spawn_compressed_body(paths.clone(), compressor)?;
                        (offer, None, Some((reader, 0)))
                    }
                }
            }
        };
        if is_cancelled(&cancel) {
            return Ok(Outcome::Failed("cancelled".into()));
        }
        let transfer_id = uuid_v4()?;
        // A streamed body knows its length; a compressed one is still being
        // prepared, so a zero length asks the transfer for it with
        // `Action::NeedUpload` once the receiver accepts.
        let chunked = matches!(&stream, Some((_, 0)));
        let body = match &stream {
            Some((_, len)) => Some((compressor, *len)),
            None => pending.as_ref().map(|_| (compressor, 0)),
        };
        let mut transfer = if chunked {
            Transfer::new_chunked(&self.config, &transfer_id, &offer, compressor)
        } else {
            Transfer::new(&self.config, &transfer_id, &offer, body)
        };
        let mut archive = match stream.take() {
            Some((reader, _)) => Some(Body::Stream(tokio::net::UnixStream::from_std(reader)?)),
            None => None,
        };

        let mut tls = tokio::select! {
            _ = wait_cancel(&mut cancel) => {
                return Ok(Outcome::Failed("cancelled".into()));
            }
            connected = self.connect(addr) => connected?,
        };
        let result = self
            .send_connected(
                &mut tls,
                &mut transfer,
                &mut archive,
                &mut pending,
                events.as_ref(),
                &mut cancel,
            )
            .await;
        if result.is_err() {
            // A normal outcome closes gracefully in send_connected. An error
            // may still have a live socket, so make the close abortive.
            abort_tls(&tls);
        }
        result
    }

    async fn send_connected(
        &self,
        tls: &mut TlsStream<TcpStream>,
        transfer: &mut Transfer,
        archive: &mut Option<Body>,
        pending: &mut Option<tokio::task::JoinHandle<io::Result<(File, u64)>>>,
        events: Option<&mpsc::UnboundedSender<Event>>,
        cancel: &mut Option<watch::Receiver<bool>>,
    ) -> io::Result<Outcome> {
        let mut buf = vec![0; 16 << 10];
        let mut timer: Option<Instant> = None;
        let mut eof = false;
        loop {
            while let Some(action) = transfer.poll() {
                match action {
                    Action::Transmit(bytes) => {
                        // Flushed, or tokio-rustls may hold it back.
                        match write(tls, &bytes, cancel).await {
                            Ok(()) => {}
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                                graceful_abort(tls).await;
                                return Ok(Outcome::Failed("cancelled".into()));
                            }
                            Err(e) => {
                                transfer.receive_eof();
                                tracing::debug!("write failed: {e}");
                            }
                        }
                    }
                    Action::SetTimer(after) => timer = after.map(|d| Instant::now() + d),
                    Action::Accepted => {
                        if let Some(events) = events {
                            let _ = events.send(Event::Accepted);
                        }
                    }
                    Action::NeedUpload => {
                        let Some(handle) = pending.take() else {
                            graceful_abort(tls).await;
                            return Err(io::Error::other("no pending upload body"));
                        };
                        match handle.await {
                            Ok(Ok((file, len))) => {
                                *archive = Some(Body::File(tokio::fs::File::from_std(file)));
                                transfer.upload_ready(len);
                            }
                            Ok(Err(e)) => {
                                graceful_abort(tls).await;
                                return Err(e);
                            }
                            Err(e) => {
                                graceful_abort(tls).await;
                                return Err(io::Error::other(e));
                            }
                        }
                    }
                    Action::SendUpload(head) => {
                        let body = archive.as_mut().expect("a file share has an archive");
                        let total = transfer.upload_size();
                        let chunked = transfer.is_chunked();
                        match upload(tls, &head, body, total, chunked, events, cancel).await {
                            Ok(()) => transfer.upload_sent(),
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                                graceful_abort(tls).await;
                                return Ok(Outcome::Failed("cancelled".into()));
                            }
                            Err(e) => {
                                // The receiver may have refused and closed;
                                // its response, if any, says why.
                                tracing::debug!("upload write failed: {e}");
                                transfer.upload_sent();
                            }
                        }
                    }
                    Action::Done(outcome) => {
                        let _ = tls.shutdown().await;
                        return Ok(outcome);
                    }
                }
            }
            tokio::select! {
                _ = wait_cancel(cancel) => {
                    graceful_abort(tls).await;
                    return Ok(Outcome::Failed("cancelled".into()));
                }
                read = tls.read(&mut buf), if !eof => match read {
                    Ok(0) | Err(_) => {
                        eof = true;
                        transfer.receive_eof();
                    }
                    Ok(n) => transfer.receive(&buf[..n]),
                },
                () = sleep_until(timer.unwrap_or_else(Instant::now)), if timer.is_some() => {
                    timer = None;
                    transfer.timeout();
                }
            }
        }
    }
}

async fn read_response<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<sender::Response> {
    let mut reader = ResponseReader::new();
    let mut buf = vec![0; 16 << 10];
    loop {
        let n = stream.read(&mut buf).await?;
        let result = if n == 0 {
            reader.receive_eof().map(Some)
        } else {
            reader.receive(&buf[..n])
        };
        match result {
            Ok(Some(response)) => return Ok(response),
            Ok(None) => {}
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

/// The upload body: a spooled file, or an archive streamed from the sources.
enum Body {
    File(tokio::fs::File),
    Stream(tokio::net::UnixStream),
}

impl Body {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Body::File(file) => file.read(buf).await,
            Body::Stream(stream) => stream.read(buf).await,
        }
    }
}

async fn upload<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    head: &[u8],
    body: &mut Body,
    total: u64,
    chunked: bool,
    events: Option<&mpsc::UnboundedSender<Event>>,
    cancel: &mut Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    write(stream, head, cancel).await?;
    let mut buf = vec![0; 64 << 10];
    let mut sent = 0u64;
    loop {
        let n = body.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if chunked {
            write(stream, format!("{n:x}\r\n").as_bytes(), cancel).await?;
            write(stream, &buf[..n], cancel).await?;
            write(stream, b"\r\n", cancel).await?;
        } else {
            write(stream, &buf[..n], cancel).await?;
        }
        sent += n as u64;
        if total > 0
            && let Some(events) = events
        {
            let _ = events.send(Event::Progress(Progress { sent, total }));
        }
    }
    if chunked {
        write(stream, b"0\r\n\r\n", cancel).await?;
    } else if sent != total {
        return Err(io::Error::other(format!(
            "the body ended at {sent} of {total} bytes"
        )));
    }
    Ok(())
}

/// Writes and flushes `bytes`, failing if the receiver stalls or the caller
/// cancels.
async fn write<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    cancel: &mut Option<watch::Receiver<bool>>,
) -> io::Result<()> {
    if is_cancelled(cancel) {
        return Err(io::Error::from(io::ErrorKind::Interrupted));
    }
    let written = async {
        stream.write_all(bytes).await?;
        stream.flush().await
    };
    tokio::select! {
        _ = wait_cancel(cancel) => Err(io::Error::from(io::ErrorKind::Interrupted)),
        result = timeout(WRITE_TIMEOUT, written) => {
            result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the receiver stopped reading"))?
        }
    }
}

fn is_cancelled(cancel: &Option<watch::Receiver<bool>>) -> bool {
    cancel.as_ref().is_some_and(|rx| *rx.borrow())
}

async fn wait_cancel(cancel: &mut Option<watch::Receiver<bool>>) {
    match cancel {
        Some(rx) => {
            if *rx.borrow() {
                return;
            }
            let _ = rx.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Close a cancelled transfer. First send a normal TLS/TCP close so the
/// kernel retransmits the FIN while a fixed-channel peer is off-channel; then
/// force an abortive close. A bare RST is sent once and is lost when the
/// iPhone is visiting another AWDL channel, which is why channel 6 cancels
/// looked successful locally but did not reach the phone.
async fn graceful_abort(tls: &mut TlsStream<TcpStream>) {
    let _ = timeout(Duration::from_secs(1), tls.shutdown()).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    abort_tls(tls);
}

/// Abortive close: `SO_LINGER=0` makes the kernel send RST when the stream is
/// dropped, so the peer stops reading instead of waiting for an idle timeout.
#[allow(deprecated)] // SO_LINGER=0 is the abortive close we want.
fn abort_tls(tls: &TlsStream<TcpStream>) {
    let _ = tls.get_ref().0.set_linger(Some(Duration::ZERO));
}

/// DVZip unless the receiver's TXT `flags` leave it out. Flags with neither
/// SupportsPipelining nor SupportsMixedTypes aren't a valid receiver's
/// (MDNS-5), such as the `0` of an instance whose TXT hasn't arrived, so
/// they say nothing and get DVZip too (UP-1b).
/// Total bytes the offer names, for choosing a compression level.
fn offer_bytes(offer: &Offer) -> u64 {
    match offer {
        Offer::Files(files) => files.iter().filter_map(|f| f.size).sum(),
        Offer::Urls(_) => 0,
    }
}

/// Above this, the archive is stored and streamed instead of compressed into
/// a temporary file.
const STORED_BODY_MIN: u64 = 512 << 20;

#[derive(Debug, Clone, Copy)]
enum BodyPlan {
    Spool,
    Stored,
    Chunked,
}

/// Extensions whose contents deflate barely or not at all.
const COMPRESSED_EXTENSIONS: &[&str] = &[
    "7z", "aab", "aac", "apk", "avi", "bin", "bz2", "dmg", "docx", "flac", "gif", "gz", "heic",
    "heif", "ipa", "iso", "jar", "jpeg", "jpg", "m4a", "m4v", "mkv", "mov", "mp3", "mp4", "ogg",
    "opus", "pdf", "png", "pptx", "rar", "webm", "webp", "xlsx", "xz", "zip", "zst",
];

fn all_compressed(paths: &[PathBuf]) -> bool {
    !paths.is_empty()
        && paths.iter().all(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .map(|e| COMPRESSED_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false)
        })
}

/// Compresses the archive straight into the pipe: no spool, no length.
fn spawn_compressed_body(
    paths: Vec<PathBuf>,
    compressor: Compressor,
) -> io::Result<std::os::unix::net::UnixStream> {
    let (tx, rx) = std::os::unix::net::UnixStream::pair()?;
    std::thread::spawn(move || {
        let mut writer = ArchiveWriter {
            encoder: Encoder::new(compressor, Compression::fast()),
            out: std::io::BufWriter::new(tx),
            ino: 1,
        };
        let result = write_entries(&mut writer, &paths).and_then(|()| writer.finish());
        if let Err(e) = result {
            tracing::debug!("compressed archive writer stopped: {e}");
        }
    });
    rx.set_nonblocking(true)?;
    Ok(rx)
}

fn compressor(receiver_flags: u32) -> Compressor {
    let known = receiver_flags & (SUPPORTS_PIPELINING | SUPPORTS_MIXED_TYPES) != 0;
    if known && receiver_flags & SUPPORTS_DVZIP == 0 {
        Compressor::Gzip
    } else {
        Compressor::DvZip
    }
}

/// A fresh transfer ID: an uppercase UUID v4 (§6.4).
fn uuid_v4() -> io::Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02X}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// The `/Ask` offer for `paths`, from metadata only: nothing is read, so the
/// receiver can prompt while the archive is still being built.
pub fn offer(paths: &[PathBuf]) -> io::Result<Offer> {
    let mut names: Vec<String> = Vec::new();
    let mut files = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(format!("{} has no UTF-8 file name", path.display())))?;
        RelPath::file_name(name).map_err(|e| invalid(e.to_string()))?;
        if names.iter().any(|n| n == name) {
            return Err(invalid(format!("two items are called {name}")));
        }
        names.push(name.to_string());
        let meta = std::fs::metadata(path)?;
        let (size, is_dir) = if meta.is_dir() {
            (Some(tree_size(path)?), true)
        } else if meta.is_file() {
            (Some(meta.len()), false)
        } else {
            return Err(invalid(format!(
                "{} isn't a file or directory",
                path.display()
            )));
        };
        files.push(AskFile {
            name: name.to_string(),
            file_type: sender::uti(name, is_dir).into(),
            size,
            bom_path: format!("./{name}"),
            is_directory: is_dir,
        });
    }
    if files.is_empty() {
        return Err(invalid("nothing to send".into()));
    }
    Ok(Offer::Files(files))
}

/// The size a directory will carry, from metadata only.
fn tree_size(path: &Path) -> io::Result<u64> {
    let meta = std::fs::metadata(path)?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        total += tree_size(&entry?.path())?;
    }
    Ok(total)
}

/// Compresses `paths` into a temporary archive, rewound with its length.
pub fn compress(
    paths: &[PathBuf],
    compressor: Compressor,
    level: Compression,
) -> io::Result<(File, u64)> {
    if paths.is_empty() {
        return Err(invalid("nothing to send".into()));
    }
    let mut spool = tempfile::tempfile()?;
    let mut writer = ArchiveWriter {
        encoder: Encoder::new(compressor, level),
        out: io::BufWriter::new(&mut spool),
        ino: 1,
    };
    write_entries(&mut writer, paths)?;
    writer.finish()?;
    let len = spool.stream_position()?;
    spool.rewind()?;
    Ok((spool, len))
}

/// The entries of the archive: the root directory, then every item, exactly
/// as [`ArchiveWriter`] would write them.
fn write_entries<W: Write>(writer: &mut ArchiveWriter<W>, paths: &[PathBuf]) -> io::Result<()> {
    writer.entry(
        &dir_entry(".", mtime(&std::fs::metadata(&paths[0])?)),
        None,
    )?;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(format!("{} has no UTF-8 file name", path.display())))?;
        RelPath::file_name(name).map_err(|e| invalid(e.to_string()))?;
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            writer.tree(path, &format!("./{name}"))?;
        } else if meta.is_file() {
            writer.file(path, &format!("./{name}"), &meta)?;
        } else {
            return Err(invalid(format!(
                "{} isn't a file or directory",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Builds the offer and the archive together. Kept for callers that want the
/// body before asking.
pub fn prepare(paths: &[PathBuf], compressor: Compressor) -> io::Result<(Offer, File, u64)> {
    let offer = offer(paths)?;
    let (file, len) = compress(paths, compressor, Compression::fast())?;
    Ok((offer, file, len))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn mtime(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// The owner a Mac's archives carry; receivers ignore it.
const UID: u32 = 501;
const GID: u32 = 20;

/// UP-2: entries for an odc archive.
pub fn file_entry(name: &str, size: u64, ino: u32, mtime: u64) -> Entry {
    Entry {
        name: name.into(),
        mode: cpio::MODE_FILE | 0o644,
        size,
        nlink: 1,
        ino,
        uid: UID,
        gid: GID,
        mtime,
    }
}

pub fn dir_entry(name: &str, mtime: u64) -> Entry {
    Entry {
        name: name.into(),
        mode: cpio::MODE_DIR | 0o755,
        size: 0,
        nlink: 2,
        ino: 0,
        uid: UID,
        gid: GID,
        mtime,
    }
}

struct ArchiveWriter<W: Write> {
    encoder: Encoder,
    out: W,
    ino: u32,
}

impl<W: Write> ArchiveWriter<W> {
    fn entry(&mut self, entry: &Entry, data: Option<&mut dyn Read>) -> io::Result<()> {
        let mut entry = entry.clone();
        entry.ino = self.ino;
        self.ino += 1;
        let header = self.encoder.write(&cpio::odc_header(&entry));
        self.out.write_all(&header)?;
        if let Some(data) = data {
            let mut left = entry.size;
            let mut buf = vec![0; 64 << 10];
            while left > 0 {
                let n = data.read(&mut buf[..(left as usize).min(64 << 10)])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "file shrank while sending",
                    ));
                }
                left -= n as u64;
                let compressed = self.encoder.write(&buf[..n]);
                self.out.write_all(&compressed)?;
            }
        }
        Ok(())
    }

    fn file(&mut self, path: &Path, name: &str, meta: &std::fs::Metadata) -> io::Result<()> {
        if meta.len() > cpio::ODC_MAX_SIZE {
            return Err(invalid(format!(
                "{} is too large for an archive",
                path.display()
            )));
        }
        let mut file = File::open(path)?;
        self.entry(
            &file_entry(name, meta.len(), 0, mtime(meta)),
            Some(&mut file),
        )
    }

    /// A directory and everything under it, in name order. Symlinks and
    /// special files are left out. Returns the total file size.
    fn tree(&mut self, path: &Path, name: &str) -> io::Result<u64> {
        self.entry(&dir_entry(name, mtime(&std::fs::metadata(path)?)), None)?;
        let mut children: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
        children.sort_by_key(|c| c.file_name());
        let mut total = 0;
        for child in children {
            let Some(child_name) = child.file_name().to_str().map(String::from) else {
                continue;
            };
            if RelPath::file_name(&child_name).is_err() {
                continue;
            }
            let meta = std::fs::symlink_metadata(child.path())?;
            let child_path = format!("{name}/{child_name}");
            if meta.is_dir() {
                total += self.tree(&child.path(), &child_path)?;
            } else if meta.is_file() {
                self.file(&child.path(), &child_path, &meta)?;
                total += meta.len();
            }
        }
        Ok(total)
    }

    fn finish(mut self) -> io::Result<()> {
        let trailer = self.encoder.write(&cpio::odc_trailer());
        self.out.write_all(&trailer)?;
        self.out.write_all(&self.encoder.finish())?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_body_is_exactly_the_length_it_claims() {
        let dir = tempfile::tempdir().unwrap();
        for (name, size) in [
            ("a", 0usize),
            ("b", 1),
            ("c", 65_535),
            ("d", 65_536),
            ("e", 70_000),
        ] {
            std::fs::write(dir.path().join(name), vec![7u8; size]).unwrap();
        }
        let paths = vec![dir.path().to_path_buf()];
        let cpio = cpio_len(&paths).unwrap();

        for compressor in [Compressor::DvZip, Compressor::Gzip] {
            // The streamed body: read it out with a patience for the
            // non-blocking fd the sender hands to tokio.
            let mut reader = spawn_stored_body(paths.clone(), compressor).unwrap();
            let mut body = Vec::new();
            let mut buf = [0u8; 64 << 10];
            loop {
                match std::io::Read::read(&mut reader, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => body.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            assert_eq!(
                body.len() as u64,
                stored_body_len(compressor, cpio),
                "{compressor:?} length"
            );
            let streamed = crate::proto::archive::compress::tests::decode_all(compressor, &body)
                .expect("the receiver decodes the streamed body");

            // The same tree, spooled by the old path.
            let (file, _) = compress(&paths, compressor, Compression::none()).unwrap();
            let mut spooled = Vec::new();
            let mut file = file;
            std::io::Read::read_to_end(&mut file, &mut spooled).unwrap();
            let spooled = crate::proto::archive::compress::tests::decode_all(compressor, &spooled)
                .expect("the receiver decodes the spooled body");
            assert_eq!(streamed, spooled, "{compressor:?} cpio");
        }
    }

    // spec: SEC-10
    #[tokio::test(start_paused = true)]
    async fn a_receiver_that_stops_reading_fails_the_upload() {
        // A pipe nobody reads: the write fills it, then waits.
        let (mut ours, _theirs) = tokio::io::duplex(1024);
        let started = Instant::now();
        let mut cancel = None;
        let e = write(&mut ours, &[0; 4096], &mut cancel)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), WRITE_TIMEOUT);
    }

    // spec: UP-1b, MDNS-5
    #[test]
    fn gzip_only_for_a_receiver_whose_flags_leave_out_dvzip() {
        assert_eq!(compressor(0x089), Compressor::Gzip);
        assert_eq!(compressor(0x08b), Compressor::DvZip);
        assert_eq!(compressor(0x3fb), Compressor::DvZip);
        // No TXT yet, or flags no valid receiver sends.
        assert_eq!(compressor(0), Compressor::DvZip);
        assert_eq!(compressor(0x001), Compressor::DvZip);
    }
}

/// Bytes of the raw odc archive `paths` produces, matching [`ArchiveWriter`]
/// entry for entry: 76-byte headers, names, then the data unpadded.
fn cpio_len(paths: &[PathBuf]) -> io::Result<u64> {
    if paths.is_empty() {
        return Err(invalid("nothing to send".into()));
    }
    let mut ino = 1u32;
    let mut total = 0u64;
    let mut root = dir_entry(".", mtime(&std::fs::metadata(&paths[0])?));
    root.ino = ino;
    ino += 1;
    total += cpio::odc_header(&root).len() as u64;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(format!("{} has no UTF-8 file name", path.display())))?;
        RelPath::file_name(name).map_err(|e| invalid(e.to_string()))?;
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            total += tree_len(path, &format!("./{name}"), &mut ino)?;
        } else if meta.is_file() {
            let mut entry = file_entry(name, meta.len(), 0, mtime(&meta));
            entry.name = format!("./{name}");
            entry.ino = ino;
            ino += 1;
            total += cpio::odc_header(&entry).len() as u64 + meta.len();
        } else {
            return Err(invalid(format!(
                "{} isn't a file or directory",
                path.display()
            )));
        }
    }
    total += cpio::odc_trailer().len() as u64;
    Ok(total)
}

fn tree_len(path: &Path, name: &str, ino: &mut u32) -> io::Result<u64> {
    let mut total = 0u64;
    let mut entry = dir_entry(name, mtime(&std::fs::metadata(path)?));
    entry.ino = *ino;
    *ino += 1;
    total += cpio::odc_header(&entry).len() as u64;
    let mut children: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
    children.sort_by_key(|c| c.file_name());
    for child in children {
        let Some(child_name) = child.file_name().to_str().map(String::from) else {
            continue;
        };
        if RelPath::file_name(&child_name).is_err() {
            continue;
        }
        let meta = std::fs::symlink_metadata(child.path())?;
        let child_path = format!("{name}/{child_name}");
        if meta.is_dir() {
            total += tree_len(&child.path(), &child_path, ino)?;
        } else if meta.is_file() {
            let mut entry = file_entry(&child_path, meta.len(), 0, mtime(&meta));
            entry.ino = *ino;
            *ino += 1;
            total += cpio::odc_header(&entry).len() as u64 + meta.len();
        }
    }
    Ok(total)
}

/// Stored deflate blocks: five bytes each, at most 65535 bytes of data.
fn stored_deflate_len(n: u64) -> u64 {
    n + 5 * (n / 65_535 + 1)
}

fn zlib_stored_len(n: u64) -> u64 {
    2 + stored_deflate_len(n) + 4
}

fn gzip_stored_len(n: u64) -> u64 {
    10 + stored_deflate_len(n) + 8
}

/// Length of the stored body for `cpio` bytes: DVZip chunks of 64 KiB, each a
/// length and its own zlib stream, or one gzip stream.
fn stored_body_len(compressor: Compressor, cpio: u64) -> u64 {
    match compressor {
        Compressor::DvZip => {
            let full = cpio / DVZIP_PIECE as u64;
            let rest = cpio % DVZIP_PIECE as u64;
            full * (4 + zlib_stored_len(DVZIP_PIECE as u64))
                + if rest > 0 { 4 + zlib_stored_len(rest) } else { 0 }
        }
        Compressor::Gzip => gzip_stored_len(cpio),
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + byte as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn write_stored_block<W: Write>(out: &mut W, data: &[u8], last: bool) -> io::Result<()> {
    let n = data.len() as u16;
    let flag = if last { 1 } else { 0 };
    out.write_all(&[flag, n as u8, (n >> 8) as u8, !n as u8, (!n >> 8) as u8])?;
    out.write_all(data)
}

/// A zlib stream with stored blocks, for one DVZip chunk.
fn write_zlib_stored<W: Write>(out: &mut W, data: &[u8]) -> io::Result<()> {
    out.write_all(&[0x78, 0x01])?;
    let mut left = data;
    loop {
        let n = left.len().min(65_535);
        write_stored_block(out, &left[..n], n == left.len())?;
        left = &left[n..];
        if left.is_empty() {
            break;
        }
    }
    out.write_all(&adler32(data).to_be_bytes())
}

struct DvZipStore<W: Write> {
    out: W,
    piece: Vec<u8>,
}

impl<W: Write> DvZipStore<W> {
    fn new(out: W) -> Self {
        DvZipStore {
            out,
            piece: Vec::with_capacity(DVZIP_PIECE),
        }
    }

    fn flush_piece(&mut self) -> io::Result<()> {
        let len = zlib_stored_len(self.piece.len() as u64) as u32;
        self.out.write_all(&len.to_be_bytes())?;
        write_zlib_stored(&mut self.out, &self.piece)?;
        self.piece.clear();
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        if !self.piece.is_empty() {
            self.flush_piece()?;
        }
        self.out.flush()
    }
}

impl<W: Write> Write for DvZipStore<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let len = data.len();
        while !data.is_empty() {
            let take = data.len().min(DVZIP_PIECE - self.piece.len());
            self.piece.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.piece.len() == DVZIP_PIECE {
                self.flush_piece()?;
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

struct GzipStore<W: Write> {
    out: W,
    buf: Vec<u8>,
    crc: flate2::Crc,
    len: u64,
}

impl<W: Write> GzipStore<W> {
    fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff])?;
        Ok(GzipStore {
            out,
            buf: Vec::with_capacity(65_535),
            crc: flate2::Crc::new(),
            len: 0,
        })
    }

    fn finish(mut self) -> io::Result<()> {
        write_stored_block(&mut self.out, &self.buf, true)?;
        self.out.write_all(&self.crc.sum().to_le_bytes())?;
        self.out.write_all(&(self.len as u32).to_le_bytes())?;
        self.out.flush()
    }
}

impl<W: Write> Write for GzipStore<W> {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let len = data.len();
        self.crc.update(data);
        self.len += len as u64;
        while !data.is_empty() {
            let take = data.len().min(65_535 - self.buf.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buf.len() == 65_535 {
                write_stored_block(&mut self.out, &self.buf, false)?;
                self.buf.clear();
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// The odc archive written the way [`ArchiveWriter`] does, into `out`.
fn write_cpio<W: Write>(out: &mut W, paths: &[PathBuf]) -> io::Result<()> {
    let mut ino = 1u32;
    let mut root = dir_entry(".", mtime(&std::fs::metadata(&paths[0])?));
    root.ino = ino;
    ino += 1;
    out.write_all(&cpio::odc_header(&root))?;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid(format!("{} has no UTF-8 file name", path.display())))?;
        RelPath::file_name(name).map_err(|e| invalid(e.to_string()))?;
        let meta = std::fs::metadata(path)?;
        if meta.is_dir() {
            write_tree(out, path, &format!("./{name}"), &mut ino)?;
        } else if meta.is_file() {
            write_file(out, path, &format!("./{name}"), &meta, &mut ino)?;
        } else {
            return Err(invalid(format!(
                "{} isn't a file or directory",
                path.display()
            )));
        }
    }
    out.write_all(&cpio::odc_trailer())
}

fn write_file<W: Write>(
    out: &mut W,
    path: &Path,
    name: &str,
    meta: &std::fs::Metadata,
    ino: &mut u32,
) -> io::Result<()> {
    if meta.len() > cpio::ODC_MAX_SIZE {
        return Err(invalid(format!(
            "{} is too large for an archive",
            path.display()
        )));
    }
    let mut entry = file_entry(name, meta.len(), 0, mtime(meta));
    entry.ino = *ino;
    *ino += 1;
    out.write_all(&cpio::odc_header(&entry))?;
    let mut file = File::open(path)?;
    let mut left = meta.len();
    let mut buf = vec![0; 64 << 10];
    while left > 0 {
        let n = file.read(&mut buf[..(left as usize).min(64 << 10)])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file shrank while sending",
            ));
        }
        left -= n as u64;
        out.write_all(&buf[..n])?;
    }
    Ok(())
}

fn write_tree<W: Write>(
    out: &mut W,
    path: &Path,
    name: &str,
    ino: &mut u32,
) -> io::Result<()> {
    let mut entry = dir_entry(name, mtime(&std::fs::metadata(path)?));
    entry.ino = *ino;
    *ino += 1;
    out.write_all(&cpio::odc_header(&entry))?;
    let mut children: Vec<_> = std::fs::read_dir(path)?.collect::<Result<_, _>>()?;
    children.sort_by_key(|c| c.file_name());
    for child in children {
        let Some(child_name) = child.file_name().to_str().map(String::from) else {
            continue;
        };
        if RelPath::file_name(&child_name).is_err() {
            continue;
        }
        let meta = std::fs::symlink_metadata(child.path())?;
        let child_path = format!("{name}/{child_name}");
        if meta.is_dir() {
            write_tree(out, &child.path(), &child_path, ino)?;
        } else if meta.is_file() {
            write_file(out, &child.path(), &child_path, &meta, ino)?;
        }
    }
    Ok(())
}

/// A body streamed from a writer thread, so a large archive never touches a
/// temporary file. The thread blocks on the pipe while the receiver is slow.
fn spawn_stored_body(
    paths: Vec<PathBuf>,
    compressor: Compressor,
) -> io::Result<std::os::unix::net::UnixStream> {
    let (tx, rx) = std::os::unix::net::UnixStream::pair()?;
    std::thread::spawn(move || {
        let out = std::io::BufWriter::new(tx);
        let result = match compressor {
            Compressor::DvZip => {
                let mut store = DvZipStore::new(out);
                write_cpio(&mut store, &paths).and_then(|()| store.finish())
            }
            Compressor::Gzip => GzipStore::new(out).and_then(|mut store| {
                write_cpio(&mut store, &paths).and_then(|()| store.finish())
            }),
        };
        if let Err(e) = result {
            tracing::debug!("stored archive writer stopped: {e}");
        }
    });
    rx.set_nonblocking(true)?;
    Ok(rx)
}
