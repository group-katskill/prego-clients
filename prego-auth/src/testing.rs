//! A small HTTP/1.1 mock server on `127.0.0.1`, for tests in this workspace. Not a public API.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// One canned response.
#[derive(Debug, Clone)]
pub struct MockResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl MockResponse {
    /// A JSON response.
    pub fn json(status: u16, body: &str) -> Self {
        MockResponse {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into(),
        }
    }

    /// Adds a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// A `307` redirect to `location`.
    pub fn redirect(location: &str) -> Self {
        MockResponse {
            status: 307,
            headers: vec![("Location".into(), location.into())],
            body: String::new(),
        }
    }
}

/// One request that the server received.
#[derive(Debug, Clone)]
pub struct MockRequest {
    /// HTTP method.
    pub method: String,
    /// Path and query.
    pub target: String,
    /// Headers with lowercase names.
    pub headers: Vec<(String, String)>,
    /// Body as text.
    pub body: String,
}

impl MockRequest {
    /// Returns the first header with this lowercase name.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    }

    /// Decodes a form-encoded body.
    pub fn form(&self) -> HashMap<String, String> {
        self.body
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (decode(k), decode(v)))
            .collect()
    }
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(b'?'));
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serves the canned responses in order, one per connection, then stops.
pub struct MockServer {
    port: u16,
    requests: Arc<Mutex<Vec<MockRequest>>>,
}

impl MockServer {
    /// Starts the server on a free port.
    pub fn start(responses: Vec<MockResponse>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for response in responses {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let mut reader = BufReader::new(stream);
                let Some(req) = read_request(&mut reader) else {
                    continue;
                };
                seen.lock().unwrap().push(req);
                let mut stream = reader.into_inner();
                let mut head = format!(
                    "HTTP/1.1 {} Mock\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (n, v) in &response.headers {
                    head.push_str(&format!("{n}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(response.body.as_bytes());
                let _ = stream.flush();
            }
        });
        MockServer { port, requests }
    }

    /// Returns `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Returns the requests received so far.
    pub fn requests(&self) -> Vec<MockRequest> {
        self.requests.lock().unwrap().clone()
    }
}

fn read_request(reader: &mut impl BufRead) -> Option<MockRequest> {
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (n, v) = h.split_once(':')?;
        headers.push((n.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let len = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;
    Some(MockRequest {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}
