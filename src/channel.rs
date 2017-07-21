use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Stdio};
use std::thread::{self, JoinHandle};
use sys;

pub type ChannelId = u32;

#[derive(Debug)]
pub struct Channel {
    id: ChannelId,
    peer_id: ChannelId,
    process: Option<process::Child>,
    pty: Option<(RawFd, PathBuf)>,
    master: Option<File>,
    window_size: u32,
    peer_window_size: u32,
    max_packet_size: u32,
    read_thread: Option<JoinHandle<()>>,
}

#[derive(Debug)]
pub enum ChannelRequest {
    Pty {
        term: String,
        chars: u16,
        rows: u16,
        pixel_width: u16,
        pixel_height: u16,
        modes: Vec<u8>,
    },
    Shell,
}

impl Channel {
    pub fn new(
        id: ChannelId, peer_id: ChannelId, peer_window_size: u32,
        max_packet_size: u32
    ) -> Channel {
        Channel {
            id: id,
            peer_id: peer_id,
            process: None,
            master: None,
            pty: None,
            window_size: peer_window_size,
            peer_window_size: peer_window_size,
            max_packet_size: max_packet_size,
            read_thread: None,
        }
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn window_size(&self) -> u32 {
        self.window_size
    }

    pub fn max_packet_size(&self) -> u32 {
        self.max_packet_size
    }

    pub fn request(&mut self, request: ChannelRequest) {
        match request
        {
            ChannelRequest::Pty {
                chars,
                rows,
                pixel_width,
                pixel_height,
                ..
            } => {
                let (master_fd, tty_path) = sys::getpty();

                sys::set_winsize(
                    master_fd,
                    chars,
                    rows,
                    pixel_width,
                    pixel_height,
                );

                self.read_thread = Some(thread::spawn(move || {
                    use libc::dup;
                    let master2 = unsafe { dup(master_fd) };

                    println!("dup result: {}", dup as u32);
                    let mut master = unsafe { File::from_raw_fd(master2) };
                    loop {
                        use std::str::from_utf8_unchecked;
                        let mut buf = [0; 4096];
                        let count = master.read(&mut buf).unwrap();
                        if count == 0 {
                            break;
                        }
                        println!("Read: {}", unsafe {
                            from_utf8_unchecked(&buf[0..count])
                        });
                    }

                    println!("Quitting read thread.");
                }));

                self.pty = Some((master_fd, tty_path));
                self.master = Some(unsafe { File::from_raw_fd(master_fd) });
            }
            ChannelRequest::Shell => {
                if let Some(&(_, ref tty_path)) = self.pty.as_ref() {
                    let stdin = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&tty_path)
                        .unwrap()
                        .into_raw_fd();

                    let stdout = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&tty_path)
                        .unwrap()
                        .into_raw_fd();

                    let stderr = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&tty_path)
                        .unwrap()
                        .into_raw_fd();

                    process::Command::new("login")
                        .stdin(unsafe { Stdio::from_raw_fd(stdin) })
                        .stdout(unsafe { Stdio::from_raw_fd(stdout) })
                        .stderr(unsafe { Stdio::from_raw_fd(stderr) })
                        .before_exec(|| sys::before_exec())
                        .spawn()
                        .unwrap();
                }
            }
        }
        debug!("Channel Request: {:?}", request);
    }

    pub fn data(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref mut master) = self.master {
            master.write_all(data)?;
            master.flush()
        }
        else {
            Ok(())
        }
    }
}
