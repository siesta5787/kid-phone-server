//! Keeps big file transfers (Google Play APKs - a game can be well over a gigabyte) from starving
//! the Pi Zero 2 W. With 512 MB of RAM, Linux happily fills memory with a file being written or
//! read, evicting the server's own code and database pages, and queues every other write (SQLite
//! on each page load and phone check-in) behind a huge backlog for the SD card. Live on a Box
//! (2026-11-19) the whole server stopped answering mid-download until it was restarted.
//!
//! So: written data is flushed every [FLUSH_EVERY] bytes and then dropped from the page cache, and
//! data streamed to phones is dropped from the cache as it goes ([CacheDroppingReader]). Plus only
//! one big download runs at a time ([DOWNLOADS]).

use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::Semaphore;

/// How much to write or read before flushing / dropping it from the page cache.
pub const FLUSH_EVERY: u64 = 8 * 1024 * 1024;

/// One big download (Google Play / GitHub release) at a time, server-wide.
pub static DOWNLOADS: Semaphore = Semaphore::const_new(1);

/// Tells the kernel this file's cached pages aren't needed any more. Only clean (already written)
/// pages are dropped, so call it after a `sync_data`. Best-effort: a failure just leaves them cached.
pub fn drop_cached(fd: RawFd) {
    // SAFETY: plain syscall on a file descriptor the caller holds open; no memory is passed.
    unsafe {
        libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

/// Wraps a file being streamed to a phone, dropping what's been read from the page cache every
/// [FLUSH_EVERY] bytes so sending a huge APK doesn't push everything else out of memory.
pub struct CacheDroppingReader {
    file: tokio::fs::File,
    fd: RawFd,
    since_drop: u64,
}

impl CacheDroppingReader {
    pub fn new(file: tokio::fs::File) -> Self {
        let fd = file.as_raw_fd();
        Self {
            file,
            fd,
            since_drop: 0,
        }
    }
}

impl AsyncRead for CacheDroppingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.file).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = (buf.filled().len() - before) as u64;
            self.since_drop += read;
            // Also at end of file (a zero-byte read), so the tail doesn't stay cached either.
            if self.since_drop >= FLUSH_EVERY || (read == 0 && self.since_drop > 0) {
                drop_cached(self.fd);
                self.since_drop = 0;
            }
        }
        result
    }
}
