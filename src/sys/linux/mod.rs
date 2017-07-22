use std::io::Result;
use std::os::unix::io::RawFd;

mod pty;
pub use self::pty::Pty;

pub fn before_exec() -> Result<()> {
    use libc;
    unsafe {
        libc::setsid();
        libc::ioctl(0, libc::TIOCSCTTY, 1);
    }
    Ok(())
}

pub fn fork() -> usize {
    use libc;
    unsafe { libc::fork() as usize }
}
