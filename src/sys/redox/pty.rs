use std::io::Result;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub fn getpty() -> (RawFd, PathBuf) {
    use syscall;

    let master = syscall::open(
        "pty:",
        syscall::O_RDWR | syscall::O_CREAT | syscall::O_NONBLOCK,
    ).unwrap();

    let mut buf: [u8; 4096] = [0; 4096];

    let count = syscall::fpath(master, &mut buf).unwrap();
    let path = String::from_utf8(Vec::from(&buf[..count]).or(())).unwrap();

    (master, PathBuf::from(path))
}
