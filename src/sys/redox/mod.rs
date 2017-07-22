use std::os::unix::io::RawFd;

pub mod pty;

pub fn before_exec() -> Result<()> {
    Ok(())
}

pub fn fork() -> usize {
    extern crate syscall;
    unsafe { syscall::clone(0).unwrap() }
}

pub fn set_winsize(fd: RawFd, row: u16, col: u16, xpixel: u16, ypixel: u16) {}
