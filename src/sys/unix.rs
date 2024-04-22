use std::io::Result;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub fn before_exec() -> Result<()> {
    unsafe {
        libc::setsid();
        libc::ioctl(0, libc::TIOCSCTTY, 1);
    }
    Ok(())
}

pub fn fork() -> usize {
    unsafe { libc::fork() as usize }
}

pub fn set_winsize(fd: RawFd, row: u16, col: u16, xpixel: u16, ypixel: u16) {
    unsafe {
        let size = libc::winsize {
            ws_row: row,
            ws_col: col,
            ws_xpixel: xpixel,
            ws_ypixel: ypixel,
        };
        libc::ioctl(fd, libc::TIOCSWINSZ, &size as *const libc::winsize);
    }
}

pub fn getpty() -> (RawFd, PathBuf) {
    use std::ffi::CStr;
    use std::fs::OpenOptions;
    use std::io::Error;
    use std::os::unix::io::IntoRawFd;

    const TIOCPKT: libc::c_ulong = 0x5420;
    extern "C" {
        fn ptsname(fd: libc::c_int) -> *const libc::c_char;
        fn grantpt(fd: libc::c_int) -> libc::c_int;
        fn unlockpt(fd: libc::c_int) -> libc::c_int;
        fn ioctl(fd: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;
    }

    let master_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ptmx")
        .unwrap()
        .into_raw_fd();

    unsafe {
        let mut flag: libc::c_int = 1;
        if ioctl(master_fd, TIOCPKT, &mut flag as *mut libc::c_int) < 0 {
            panic!("ioctl: {:?}", Error::last_os_error());
        }
        if grantpt(master_fd) < 0 {
            panic!("grantpt: {:?}", Error::last_os_error());
        }
        if unlockpt(master_fd) < 0 {
            panic!("unlockpt: {:?}", Error::last_os_error());
        }
    }

    let tty_path = unsafe {
        PathBuf::from(
            CStr::from_ptr(ptsname(master_fd))
                .to_string_lossy()
                .into_owned(),
        )
    };
    (master_fd, tty_path)
}
