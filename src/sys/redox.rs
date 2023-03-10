use std::io::Result;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub fn before_exec() -> Result<()> {
    Ok(())
}

pub fn fork() -> usize {
    extern crate syscall;
    unsafe { syscall::clone(syscall::CloneFlags::empty()).unwrap() }
}

pub fn set_winsize(fd: RawFd, row: u16, col: u16, xpixel: u16, ypixel: u16) {}

pub fn getpty() -> (RawFd, PathBuf) {
    use syscall;

    let master = syscall::open("pty:", syscall::O_RDWR | syscall::O_CREAT)
        .unwrap();

    let mut buf: [u8; 4096] = [0; 4096];

    let count = syscall::fpath(master, &mut buf).unwrap();
    (
        master as i32,
        PathBuf::from(unsafe {
            String::from_utf8_unchecked(Vec::from(&buf[..count]))
        }),
    )
}
