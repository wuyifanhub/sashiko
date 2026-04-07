// Copyright 2026 The Sashiko Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! POP3/POP3S client implementation

use anyhow::{anyhow, Result};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

#[derive(Debug, Clone, PartialEq)]
pub enum Pop3State {
    Authorization,
    Transaction,
    Closed,
}

pub struct TlsStreamWrapper {
    stream: tokio_native_tls::TlsStream<TcpStream>,
}

impl TlsStreamWrapper {
    async fn new(host: &str, tcp_stream: TcpStream) -> Result<Self> {
        let connector = native_tls::TlsConnector::new()?;
        let tls_stream = tokio_native_tls::TlsConnector::from(connector)
            .connect(host, tcp_stream)
            .await?;
        Ok(Self { stream: tls_stream })
    }
}

impl AsyncRead for TlsStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub struct Pop3Client<S> {
    stream: tokio::io::BufReader<S>,
    state: Pop3State,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Pop3Client<S> {
    pub async fn quit(&mut self) -> Result<()> {
        self.send_command("QUIT").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            debug!("QUIT response was not +OK: {}", response);
        }
        self.state = Pop3State::Closed;
        Ok(())
    }

    pub async fn user(&mut self, username: &str) -> Result<()> {
        self.send_command(&format!("USER {}", username)).await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("USER command failed: {}", response));
        }
        Ok(())
    }

    pub async fn pass(&mut self, password: &str) -> Result<()> {
        self.send_command(&format!("PASS {}", password)).await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("PASS command failed: {}", response));
        }
        self.state = Pop3State::Transaction;
        Ok(())
    }

    pub async fn auth(&mut self, username: &str, password: &str) -> Result<()> {
        self.user(username).await?;
        self.pass(password).await
    }

    pub async fn stat(&mut self) -> Result<(u32, u64)> {
        self.send_command("STAT").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("STAT command failed: {}", response));
        }
        let parts: Vec<&str> = response.split_whitespace().skip(1).collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid STAT response: {}", response));
        }
        let count: u32 = parts[0].parse().unwrap_or(0);
        let size: u64 = parts[1].parse().unwrap_or(0);
        Ok((count, size))
    }

    pub async fn list(&mut self) -> Result<Vec<MailInfo>> {
        self.send_command("LIST").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("LIST command failed: {}", response));
        }
        let mut messages = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line == "." {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let (Ok(id), Ok(size)) = (parts[0].parse::<u32>(), parts[1].parse::<u64>()) {
                    messages.push(MailInfo { id, size });
                }
            }
        }
        Ok(messages)
    }

    pub async fn uidl(&mut self) -> Result<Vec<UidInfo>> {
        self.send_command("UIDL").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("UIDL command failed: {}", response));
        }
        let mut uids = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line == "." {
                break;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(id) = parts[0].parse::<u32>() {
                    uids.push(UidInfo { id, uid: parts[1].to_string() });
                }
            }
        }
        Ok(uids)
    }

    pub async fn retr(&mut self, msg_id: u32) -> Result<Vec<String>> {
        self.send_command(&format!("RETR {}", msg_id)).await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("RETR command failed: {}", msg_id));
        }
        let mut lines = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line == "." {
                break;
            }
            let content = if line.starts_with("..") {
                line[1..].to_string()
            } else {
                line
            };
            lines.push(content);
        }
        Ok(lines)
    }

    pub async fn top(&mut self, msg_id: u32, lines: u32) -> Result<Vec<String>> {
        self.send_command(&format!("TOP {} {}", msg_id, lines)).await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("TOP command failed: {}", msg_id));
        }
        let mut result_lines = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line == "." {
                break;
            }
            let content = if line.starts_with("..") {
                line[1..].to_string()
            } else {
                line
            };
            result_lines.push(content);
        }
        Ok(result_lines)
    }

    pub async fn dele(&mut self, msg_id: u32) -> Result<()> {
        self.send_command(&format!("DELE {}", msg_id)).await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("DELE command failed: {}", msg_id));
        }
        Ok(())
    }

    pub async fn noop(&mut self) -> Result<()> {
        self.send_command("NOOP").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("NOOP command failed: {}", response));
        }
        Ok(())
    }

    pub async fn reset(&mut self) -> Result<()> {
        self.send_command("RSET").await?;
        let response = self.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("RSET command failed: {}", response));
        }
        Ok(())
    }

    pub fn state(&self) -> Pop3State {
        self.state.clone()
    }

    async fn send_command(&mut self, command: &str) -> Result<()> {
        self.stream.write_all(command.as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn read_response(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        self.stream.read_until(b'\n', &mut buf).await?;
        Ok(String::from_utf8_lossy(&buf).trim_end().to_string())
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut buf = Vec::new();
        let n = self.stream.read_until(b'\n', &mut buf).await?;
        if n == 0 {
            return Err(anyhow!("Unexpected EOF"));
        }
        Ok(String::from_utf8_lossy(&buf).trim_end().to_string())
    }
}

impl Pop3Client<TlsStreamWrapper> {
    pub async fn connect_ssl(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        info!("Connecting to POP3S at {}", addr);
        let tcp_stream = TcpStream::connect(&addr).await?;
        let tls_stream = TlsStreamWrapper::new(host, tcp_stream).await?;
        let mut client = Self {
            stream: tokio::io::BufReader::new(tls_stream),
            state: Pop3State::Authorization,
        };
        let response = client.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("Unexpected welcome: {}", response));
        }
        debug!("Connected: {}", response);
        Ok(client)
    }
}

impl Pop3Client<TcpStream> {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        info!("Connecting to POP3 at {}", addr);
        let stream = TcpStream::connect(&addr).await?;
        let mut client = Self {
            stream: tokio::io::BufReader::new(stream),
            state: Pop3State::Authorization,
        };
        let response = client.read_response().await?;
        if !response.starts_with("+OK") {
            return Err(anyhow!("Unexpected welcome: {}", response));
        }
        debug!("Connected: {}", response);
        Ok(client)
    }
}

#[derive(Debug, Clone)]
pub struct MailInfo {
    pub id: u32,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct UidInfo {
    pub id: u32,
    pub uid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pop3_state() {
        assert_eq!(Pop3State::Authorization, Pop3State::Authorization);
        assert_ne!(Pop3State::Authorization, Pop3State::Transaction);
    }
}
