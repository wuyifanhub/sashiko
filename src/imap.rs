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

//! IMAP/IMAPS client implementation

use anyhow::{anyhow, Result};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

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

#[derive(Debug, Clone, PartialEq)]
pub enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub struct ImapClient<S> {
    stream: tokio::io::BufReader<S>,
    tag_counter: u32,
    state: ImapState,
}

#[derive(Debug, Clone)]
pub struct MailboxInfo {
    pub name: String,
    pub delimiter: String,
}

#[derive(Debug, Clone)]
pub struct MailboxStatus {
    pub exists: u32,
    pub recent: u32,
    pub uid_next: u32,
    pub uid_validity: u32,
}

#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub message_num: u32,
    pub uid: Option<u64>,
    pub size: Option<u64>,
    pub body: Option<Vec<String>>,
    pub envelope: Option<Envelope>,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub subject: Option<String>,
    pub from: Option<String>,
    pub message_id: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ImapClient<S> {
    fn next_tag(&mut self) -> String {
        self.tag_counter += 1;
        format!("A{:04}", self.tag_counter)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let tag = self.next_tag();
        let cmd = format!("{} LOGIN {} {}", tag, quote_string(username), quote_string(password));
        self.send_command(&cmd).await?;
        // Loop until we get the tagged response (skip untagged responses like CAPABILITY)
        loop {
            let response = self.read_line().await?;
            if response.starts_with(&format!("{} ", tag)) {
                if response.contains(" OK") {
                    self.state = ImapState::Authenticated;
                    return Ok(());
                } else {
                    return Err(anyhow!("LOGIN failed: {}", response));
                }
            }
            // Skip untagged responses
        }
    }

    pub async fn list(&mut self, reference: &str, mailbox: &str) -> Result<Vec<MailboxInfo>> {
        let tag = self.next_tag();
        let cmd = format!("{} LIST {} {}", tag, quote_string(reference), quote_string(mailbox));
        self.send_command(&cmd).await?;
        let mut mailboxes = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line.starts_with(&format!("{} ", tag)) {
                if !line.contains("OK") {
                    return Err(anyhow!("LIST failed: {}", line));
                }
                break;
            }
            if line.starts_with("* LIST") {
                if let Some(info) = parse_list_response(&line) {
                    mailboxes.push(info);
                }
            }
        }
        Ok(mailboxes)
    }

    pub async fn select(&mut self, mailbox: &str) -> Result<MailboxStatus> {
        let tag = self.next_tag();
        let cmd = format!("{} SELECT {}", tag, quote_string(mailbox));
        self.send_command(&cmd).await?;
        let mut status = MailboxStatus { exists: 0, recent: 0, uid_next: 0, uid_validity: 0 };
        loop {
            let line = self.read_line().await?;
            if line.starts_with(&format!("{} ", tag)) {
                if !line.contains("OK") {
                    return Err(anyhow!("SELECT failed: {}", line));
                }
                break;
            }
            if line.starts_with("* ") {
                let content = &line[2..];
                if content.starts_with("EXISTS") {
                    status.exists = parse_number(content);
                } else if content.starts_with("RECENT") {
                    status.recent = parse_number(content);
                } else if content.starts_with("UIDNEXT") {
                    status.uid_next = parse_number(content);
                } else if content.starts_with("UIDVALIDITY") {
                    status.uid_validity = parse_number(content);
                }
            }
        }
        self.state = ImapState::Selected;
        Ok(status)
    }

    pub async fn search(&mut self, charset: Option<&str>, criteria: &str) -> Result<Vec<u32>> {
        let tag = self.next_tag();
        let cmd = if let Some(c) = charset {
            format!("{} SEARCH CHARSET {} {}", tag, c, criteria)
        } else {
            format!("{} SEARCH {}", tag, criteria)
        };
        self.send_command(&cmd).await?;
        let mut results = Vec::new();
        loop {
            let line = self.read_line().await?;
            if line.starts_with(&format!("{} ", tag)) {
                if !line.contains("OK") {
                    return Err(anyhow!("SEARCH failed: {}", line));
                }
                break;
            }
            if line.starts_with("* SEARCH") {
                for part in line.split_whitespace().skip(1) {
                    if let Ok(num) = part.parse::<u32>() {
                        results.push(num);
                    }
                }
            }
        }
        Ok(results)
    }

    pub async fn fetch(&mut self, sequence: &str, items: &[&str]) -> Result<Vec<FetchResponse>> {
        let tag = self.next_tag();
        let items_str = items.join(" ");
        let cmd = format!("{} FETCH {} ({})", tag, sequence, items_str);
        self.send_command(&cmd).await?;
        let mut responses = Vec::new();
        let mut current: Option<FetchResponse> = None;
        loop {
            let line = self.read_line().await?;
            if line.starts_with(&format!("{} ", tag)) {
                if !line.contains("OK") {
                    return Err(anyhow!("FETCH failed: {}", line));
                }
                break;
            }
            if line.starts_with("* ") && line.contains(" FETCH ") {
                if let Some(response) = parse_fetch_response(&line)? {
                    if let Some(prev) = current.take() {
                        responses.push(prev);
                    }
                    current = Some(response);
                }
            }
        }
        if let Some(final_response) = current {
            responses.push(final_response);
        }
        Ok(responses)
    }

    pub async fn logout(&mut self) -> Result<()> {
        let tag = self.next_tag();
        let cmd = format!("{} LOGOUT", tag);
        self.send_command(&cmd).await?;
        loop {
            let line = self.read_line().await?;
            if line.starts_with(&format!("{} ", tag)) {
                break;
            }
        }
        self.state = ImapState::Logout;
        Ok(())
    }

    pub fn state(&self) -> ImapState {
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

impl ImapClient<TlsStreamWrapper> {
    pub async fn connect_ssl(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        info!("Connecting to IMAPS at {}", addr);
        let tcp_stream = TcpStream::connect(&addr).await?;
        let tls_stream = TlsStreamWrapper::new(host, tcp_stream).await?;
        let mut client = Self {
            stream: tokio::io::BufReader::new(tls_stream),
            tag_counter: 0,
            state: ImapState::NotAuthenticated,
        };
        let greeting = client.read_line().await?;
        debug!("IMAP greeting: {}", greeting);
        if greeting.starts_with("* OK") {
            client.state = ImapState::NotAuthenticated;
        } else {
            return Err(anyhow!("Unexpected greeting: {}", greeting));
        }
        Ok(client)
    }
}

impl ImapClient<TcpStream> {
    pub async fn connect(host: &str, port: u16) -> Result<Self> {
        let addr = format!("{}:{}", host, port);
        info!("Connecting to IMAP at {}", addr);
        let stream = TcpStream::connect(&addr).await?;
        let mut client = Self {
            stream: tokio::io::BufReader::new(stream),
            tag_counter: 0,
            state: ImapState::NotAuthenticated,
        };
        let greeting = client.read_line().await?;
        debug!("IMAP greeting: {}", greeting);
        if greeting.starts_with("* OK") {
            client.state = ImapState::NotAuthenticated;
        } else {
            return Err(anyhow!("Unexpected greeting: {}", greeting));
        }
        Ok(client)
    }
}

fn quote_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn parse_number(line: &str) -> u32 {
    line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn parse_list_response(line: &str) -> Option<MailboxInfo> {
    let after_list = line.strip_prefix("* LIST ")?;
    let parts: Vec<&str> = after_list.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let name = parts.last()?.trim_matches('"').to_string();
    let delimiter = parts[parts.len() - 2].trim_matches('"').to_string();
    Some(MailboxInfo { name, delimiter })
}

fn parse_fetch_response(line: &str) -> Result<Option<FetchResponse>> {
    let after_fetch = line.split_once(" FETCH ").ok_or_else(|| anyhow!("Invalid FETCH"))?.1;
    let before_fetch = line.split_once(" FETCH ").unwrap().0;
    let msg_num: u32 = before_fetch.strip_prefix("* ").and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let mut response = FetchResponse { message_num: msg_num, uid: None, size: None, body: None, envelope: None };
    let content = after_fetch.trim();
    if content.starts_with('(') && content.ends_with(')') {
        let inner = &content[1..content.len() - 1];
        parse_fetch_attributes(inner, &mut response)?;
    }
    Ok(Some(response))
}

fn parse_fetch_attributes(content: &str, response: &mut FetchResponse) -> Result<()> {
    let mut current = String::new();
    let mut depth = 0;
    let mut in_string = false;
    for i in 0..content.len() {
        let c = content.chars().nth(i).unwrap();
        if c == '"' && (i == 0 || content.chars().nth(i - 1) != Some('\\')) {
            in_string = !in_string;
        }
        if !in_string {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && !current.is_empty() {
                        process_attribute(current.trim(), response);
                        current.clear();
                    }
                }
                ' ' if depth == 0 => {
                    if !current.is_empty() {
                        process_attribute(current.trim(), response);
                        current.clear();
                    }
                }
                _ => current.push(c),
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        process_attribute(current.trim(), response);
    }
    Ok(())
}

fn process_attribute(attr: &str, response: &mut FetchResponse) {
    if attr.starts_with("UID ") {
        if let Ok(uid) = attr[4..].parse::<u64>() {
            response.uid = Some(uid);
        }
    } else if attr.starts_with("RFC822.SIZE ") {
        if let Ok(size) = attr[13..].parse::<u64>() {
            response.size = Some(size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quote_string() {
        assert_eq!(quote_string("hello"), "\"hello\"");
    }

    #[test]
    fn test_imap_state() {
        assert_eq!(ImapState::NotAuthenticated, ImapState::NotAuthenticated);
    }
}
