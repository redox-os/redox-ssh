use libc;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};

pub struct Pty {
    master: File,
    path: PathBuf,
    sub_thread: Option<JoinHandle<()>>,
    sub_thread_tx: Option<mpsc::Sender<ThreadCommand>>,
}

enum ThreadCommand {
    WaitForData,
    Stop,
}

impl Pty {
    pub fn get() -> Result<Pty, ()> {
        const TIOCPKT: libc::c_ulong = 0x5420;

        let master_fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/ptmx")
            .unwrap()
            .into_raw_fd();

        unsafe {
            use std::io::Error;
            let mut flag: libc::c_int = 1;

            if libc::ioctl(
                master_fd,
                TIOCPKT,
                &mut flag as *mut libc::c_int,
            ) < 0
            {
                error!("ioctl: {:?}", Error::last_os_error());
                return Err(());
            }
            if libc::grantpt(master_fd) < 0 {
                error!("grantpt: {:?}", Error::last_os_error());
                return Err(());
            }
            if libc::unlockpt(master_fd) < 0 {
                error!("unlockpt: {:?}", Error::last_os_error());
                return Err(());
            }
        }

        let tty_path = unsafe {
            PathBuf::from(
                CStr::from_ptr(libc::ptsname(master_fd))
                    .to_string_lossy()
                    .into_owned(),
            )
        };

        let master = unsafe { File::from_raw_fd(master_fd) };

        Ok(Pty {
            master: master,
            path: tty_path,
            sub_thread: None,
            sub_thread_tx: None,
        })
    }

    pub fn subscribe<F>(&mut self, callback: F)
    where
        F: Fn() -> Result<(), ()> + Send + 'static,
    {
        let (thread_tx, thread_rx) = mpsc::channel();

        let mut pollfd = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        self.sub_thread = Some(thread::spawn(move || {
            loop {
                match thread_rx.recv()
                {
                    Ok(ThreadCommand::WaitForData) => {}
                    Ok(ThreadCommand::Stop) => return,
                    Err(_) => return,
                }

                // Clear receive queue
                while !thread_rx.try_recv().is_err() {}

                unsafe { libc::poll(&mut pollfd as *mut libc::pollfd, 1, -1) };
                if callback().is_err() {
                    return;
                }
            }
        }));

        self.sub_thread_tx = Some(thread_tx);
    }

    pub fn path<'a>(&'a self) -> &'a PathBuf {
        &self.path
    }

    pub fn set_winsize(&self, row: u16, col: u16, xpixel: u16, ypixel: u16) {
        let size = libc::winsize {
            ws_row: row,
            ws_col: col,
            ws_xpixel: xpixel,
            ws_ypixel: ypixel,
        };

        unsafe {
            let fd = self.master.as_raw_fd();
            libc::ioctl(fd, libc::TIOCSWINSZ, &size as *const libc::winsize);
        }
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.master.write_all(data)?;
        self.master.flush()
    }

    pub fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        match self.master.read(data)
        {
            Ok(count) => {
                self.sub_thread_tx.as_ref().map(|tx| {
                    tx.send(ThreadCommand::WaitForData)
                });
                Ok(count)
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.sub_thread_tx.as_ref().map(|tx| {
                    tx.send(ThreadCommand::WaitForData)
                });
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        self.sub_thread_tx.take().map(
            |tx| tx.send(ThreadCommand::Stop),
        );
        self.sub_thread = None;
    }
}
