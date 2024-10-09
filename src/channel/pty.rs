use std::{
    fs::File,
    io::{Read, Write},
    os::fd::FromRawFd,
    thread,
};

use crate::sys;

use super::Channel;

#[derive(Debug)]
pub struct PtyConfig {
    pub term: String,
    pub chars: u16,
    pub rows: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
    pub modes: Vec<u8>,
}

impl Channel {
    /// Allocates and sets up new PTY.
    /// TODO: consider what to do if there already is a PTY.
    ///
    /// Also does incorrect error handling internally
    /// on I/O errors and occurs if a process exits.
    pub fn setup_tty(
        &mut self,
        PtyConfig {
            term,
            chars,
            rows,
            pixel_width,
            pixel_height,
            modes,
        }: &PtyConfig,
    ) {
        let (master_fd, tty_path) = sys::getpty();

        sys::set_winsize(master_fd, *chars, *rows, *pixel_width, *pixel_height);

        self.read_thread = Some(thread::spawn(move || {
            #[cfg(target_os = "redox")]
            let master2 =
                unsafe { syscall::dup(master_fd as usize, &[]).unwrap_or(!0) };
            #[cfg(not(target_os = "redox"))]
            let master2 = unsafe { libc::dup(master_fd) };

            println!("dup result: {}", master2 as u32);
            let mut master = unsafe { File::from_raw_fd(master2 as i32) };
            loop {
                use std::str::from_utf8_unchecked;

                let mut buf = [0; 4096];
                let count = match master.read(&mut buf) {
                    Ok(o) => o,
                    Err(e) => {
                        warn!("Error occured, ignoring: {}", e);
                        1 // TODO
                    }
                };

                // This is weird.
                // An error is thrown&unwrapped here (panic)
                // but yet it continues to function properly
                if count == 0 {
                    break;
                }
                let data_read = unsafe { from_utf8_unchecked(&buf[0..count]) };
                println!("Read: {}", data_read);
            }

            println!("Quitting read thread.");
        }));

        self.pty = Some((master_fd, tty_path));
        self.master = Some(unsafe { File::from_raw_fd(master_fd) });
    }
}
