use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Stdio};
use sys::{before_exec, getpty};

pub type ChannelId = u32;

#[derive(Debug)]
pub struct Channel {
    id: ChannelId,
    peer_id: ChannelId,
    process: Option<process::Child>,
    pty: Option<(RawFd, PathBuf)>,
    master: Option<File>,
    stdio: Option<(File, File, File)>,
    window_size: u32,
    peer_window_size: u32,
    max_packet_size: u32,
}

#[derive(Debug)]
pub enum ChannelRequest {
    Pty {
        term: String,
        char_width: u32,
        row_height: u32,
        pixel_width: u32,
        pixel_height: u32,
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
            stdio: None,
            window_size: peer_window_size,
            peer_window_size: peer_window_size,
            max_packet_size: max_packet_size,
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
            ChannelRequest::Pty { .. } => {
                let (master_fd, tty_path) = getpty();

                let stdin = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&tty_path)
                    .unwrap();

                let stdout = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&tty_path)
                    .unwrap();

                let stderr = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&tty_path)
                    .unwrap();

                self.stdio = Some((stdin, stdout, stderr));
                self.master = Some(unsafe { File::from_raw_fd(master_fd) });
            }
            ChannelRequest::Shell => {
                if let Some((ref stdin, ref stdout, ref stderr)) = self.stdio {
                    process::Command::new("login")
                        .stdin(unsafe { Stdio::from_raw_fd(stdin.as_raw_fd()) })
                        .stdout(
                            unsafe { Stdio::from_raw_fd(stdout.as_raw_fd()) },
                        )
                        .stderr(
                            unsafe { Stdio::from_raw_fd(stderr.as_raw_fd()) },
                        )
                        .before_exec(|| before_exec())
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

    pub fn read(&mut self) -> io::Result<Vec<u8>> {
        if let Some(ref mut master) = self.master {
            let mut buf = [0; 4096];
            let count = master.read(&mut buf)?;
            Ok(buf[0..count].to_vec())
        }
        else {
            Ok(b"".to_vec())
        }
    }
}
