use std::{
    fs::OpenOptions,
    io::{stdin, BufReader},
    os::{
        fd::{FromRawFd, IntoRawFd, RawFd},
        unix::process::CommandExt,
    },
    path::PathBuf,
    process::{self, ChildStderr, ChildStdin, ChildStdout, Stdio},
};

use crate::sys;

use super::Channel;

#[derive(Debug)]
pub struct PipeContainer {
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    pub stderr: BufReader<ChildStderr>,
}

impl Channel {
    pub fn setup_shell(&mut self) {
        match self.pty.as_ref() {
            Some((_, tty_path)) => with_tty(tty_path),
            None => {
                let pipes = self.without_tty();
                #[cfg(unix)]
                use crate::sys::non_blockify_reader;
                non_blockify_reader(pipes.stdout.get_ref());
                non_blockify_reader(pipes.stderr.get_ref());
                self.pipes = Some(pipes);
            }
        }
    }

    fn without_tty(&mut self) -> PipeContainer {
        let mut args = self.executable.split_ascii_whitespace();
        let exec = args.next().expect("Failed to get executable from args.");

        info!("Executable {exec}, args: {args:?}");

        let proc = unsafe {
            process::Command::new(exec)
                // .env_clear()
                .args(args)
                .envs(self.env.drain(..))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .pre_exec(sys::before_exec)
                .spawn()
                .unwrap()
        };

        PipeContainer {
            stdin: proc.stdin.unwrap(),
            stdout: BufReader::with_capacity(1, proc.stdout.unwrap()),
            stderr: BufReader::with_capacity(1, proc.stderr.unwrap()),
        }
    }
}

fn with_tty(tty_path: &PathBuf) {
    let stdin = open_tty(tty_path, true, true);
    let stdout = open_tty(tty_path, true, true);
    let stderr = open_tty(tty_path, true, true);

    unsafe {
        process::Command::new("/bin/sh")
            .stdin(Stdio::from_raw_fd(stdin))
            .stdout(Stdio::from_raw_fd(stdout))
            .stderr(Stdio::from_raw_fd(stderr))
            .pre_exec(sys::before_exec)
    }
    .spawn()
    .unwrap();

    // TODO: TTY is broken
}

fn open_tty(tty_path: &PathBuf, read: bool, write: bool) -> RawFd {
    OpenOptions::new()
        .read(read)
        .write(write)
        .open(tty_path)
        .unwrap()
        .into_raw_fd()
}
