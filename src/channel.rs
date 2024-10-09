mod pty;
mod shell;

use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process;
use std::thread::JoinHandle;

pub use pty::PtyConfig;
use shell::PipeContainer;

pub type ChannelId = u32;

#[derive(Debug)]
/// TODO: Split into channel types, i.e. `PtyChannel` and `ShellChannel`
pub struct Channel {
    id: ChannelId,
    peer_id: ChannelId,
    process: Option<process::Child>,
    pty: Option<(RawFd, PathBuf)>,
    pipes: Option<PipeContainer>,
    master: Option<File>,
    window_size: u32,
    peer_window_size: u32,
    max_packet_size: u32,
    read_thread: Option<JoinHandle<()>>,
    env: Vec<(String, String)>,
    executable: String,
}

#[derive(Debug)]
pub enum ChannelRequest {
    Pty(PtyConfig),
    Shell,
    Env(String, String),
    Exec(String),
}

impl Channel {
    pub fn new(
        id: ChannelId,
        peer_id: ChannelId,
        peer_window_size: u32,
        max_packet_size: u32,
    ) -> Self {
        Self {
            id,
            peer_id,
            process: None,
            master: None,
            pty: None,
            pipes: None,
            window_size: peer_window_size,
            peer_window_size,
            max_packet_size,
            read_thread: None,
            env: Vec::new(),
            executable: "/bin/sh".to_string(),
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

    pub fn handle_request(&mut self, request: ChannelRequest) {
        debug!("Channel Request: {:?}", request);
        match request {
            ChannelRequest::Pty(ref pty) => self.setup_tty(pty),
            ChannelRequest::Shell => self.setup_shell(),
            ChannelRequest::Env(key, value) => self.env.push((key, value)),
            ChannelRequest::Exec(executable) => {
                self.executable = executable;
                self.setup_shell();
            }
        }
    }

    /// Writes `data` **to** this channel;
    pub fn write_data(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(ref mut master) = self.master {
            master.write_all(data)?;
            master.flush()
        }
        else if let Some(PipeContainer { ref mut stdin, .. }) = self.pipes {
            stdin.write_all(data)?;
            stdin.flush()
        }
        else {
            Ok(())
        }
    }

    /// Reads data **from** this channel and writes it **to** the buffer/.
    pub fn read_pty_master(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(ref mut master) = self.master {
            master.read(buf)
        }
        else {
            Ok(0)
        }
    }

    /// Reads data **from** this channel and writes it **to** the buffer/.
    pub fn read_stdout(&mut self, buf: &mut String) -> io::Result<usize> {
        if let Some(pipes) = &mut self.pipes {
            pipes.stdout.read_line(buf)
        }
        else {
            Ok(0)
        }
    }

    pub fn read_stderr(&mut self, buf: &mut String) -> io::Result<usize> {
        if let Some(pipes) = &mut self.pipes {
            pipes.stderr.read_line(buf)
        }
        else {
            Ok(0)
        }
    }
}
