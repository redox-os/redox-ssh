use std::io::Result;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub fn before_exec() -> Result<()> {
    Ok(())
}

pub fn fork() -> usize {
    todo!(
        "You must specify -f, the old forking for Redox doesn't work anyway."
    );
    // The following on't work anyway
    // but will panic due to missing implementation
    // extern crate syscall;
    // unsafe { syscall::clone(syscall::CloneFlags::empty()).unwrap() }
}

pub fn set_winsize(fd: RawFd, row: u16, col: u16, xpixel: u16, ypixel: u16) {}

pub fn getpty() -> (RawFd, PathBuf) {
    use libredox::{call, flag};

    let master = call::open("pty:", flag::O_RDWR | flag::O_CREAT, 777).unwrap();

    let mut buf: [u8; 4096] = [0; 4096];

    let count = call::fpath(master, &mut buf).unwrap();
    (
        master as i32,
        PathBuf::from(unsafe {
            String::from_utf8_unchecked(Vec::from(&buf[..count]))
        }),
    )
}

/// Sets the file descriptor to non-blocking mode.
/// This uses the **`unsafe`** keyword
pub fn non_blockify_reader(obj: &impl AsRawFd) {
    todo!();
}
