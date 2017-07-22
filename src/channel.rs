use std::fs::OpenOptions;
use std::io;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::{self, Stdio};
use std::sync::mpsc;
use sys;

use connection::ConnectionEvent;

pub type ChannelId = u32;

pub struct Channel {
    id: ChannelId,
    peer_id: ChannelId,
    process: Option<process::Child>,
    pty: Option<sys::Pty>,
    window_size: u32,
    peer_window_size: u32,
    max_packet_size: u32,
    events: mpsc::Sender<ConnectionEvent>,
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
        max_packet_size: u32, events: mpsc::Sender<ConnectionEvent>
    ) -> Channel {
        Channel {
            id: id,
            peer_id: peer_id,
            process: None,
            pty: None,
            window_size: peer_window_size,
            peer_window_size: peer_window_size,
            max_packet_size: max_packet_size,
            events: events,
        }
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    pub fn peer_id(&self) -> ChannelId {
        self.peer_id
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
                if let Ok(mut pty) = sys::Pty::get() {
                    pty.set_winsize(chars, rows, pixel_width, pixel_height);

                    let events = self.events.clone();
                    let id = self.id;

                    pty.subscribe(move || {
                        events.send(ConnectionEvent::ChannelData(id)).map_err(
                            |_| (),
                        )
                    });

                    self.pty = Some(pty);
                }
            }
            ChannelRequest::Shell => {
                if let Some(ref pty) = self.pty {
                    let stdin = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(pty.path())
                        .unwrap()
                        .into_raw_fd();

                    let stdout = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(pty.path())
                        .unwrap()
                        .into_raw_fd();

                    let stderr = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(pty.path())
                        .unwrap()
                        .into_raw_fd();

                    self.process = Some(
                        process::Command::new("login")
                            .stdin(unsafe { Stdio::from_raw_fd(stdin) })
                            .stdout(unsafe { Stdio::from_raw_fd(stdout) })
                            .stderr(unsafe { Stdio::from_raw_fd(stderr) })
                            .before_exec(|| sys::before_exec())
                            .spawn()
                            .unwrap(),
                    );
                }
            }
        }
        debug!("Channel Request: {:?}", request);
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        match self.pty
        {
            Some(ref mut pty) => pty.write(data),
            _ => Ok(()),
        }
    }

    pub fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        match self.pty
        {
            Some(ref mut pty) => pty.read(data),
            _ => Ok(0),
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.process.take().map(|mut p| p.kill());
    }
}
