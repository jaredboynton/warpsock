use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use tokio::sync::Mutex;

use ::specter::{Client as RustClient, Message, WebSocket as RustWebSocket};

use crate::ws_types::{CloseFrame, WebSocketMessage};

#[pyclass]
pub struct WebSocketBuilder {
    client: RustClient,
    url: String,
    headers: Vec<(String, String)>,
    subprotocols: Vec<String>,
    max_message_size: Option<usize>,
    max_frame_size: Option<usize>,
    connect_timeout: Option<f64>,
    handshake_timeout: Option<f64>,
    read_timeout: Option<f64>,
    write_timeout: Option<f64>,
}

#[pyclass]
pub struct WebSocket {
    inner: Arc<Mutex<RustWebSocket>>,
    url: String,
    protocol: Option<String>,
}

impl WebSocketBuilder {
    pub(crate) fn from_client(client: RustClient, url: String) -> Self {
        Self {
            client,
            url,
            headers: Vec::new(),
            subprotocols: Vec::new(),
            max_message_size: None,
            max_frame_size: None,
            connect_timeout: None,
            handshake_timeout: None,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

#[pymethods]
impl WebSocketBuilder {
    fn header(&mut self, key: String, value: String) -> PyResult<()> {
        self.headers.push((key, value));
        Ok(())
    }

    fn headers(&mut self, headers: Vec<(String, String)>) -> PyResult<()> {
        self.headers = headers;
        Ok(())
    }

    fn subprotocol(&mut self, value: String) -> PyResult<()> {
        self.subprotocols.push(value);
        Ok(())
    }

    fn subprotocols(&mut self, values: Vec<String>) -> PyResult<()> {
        self.subprotocols.extend(values);
        Ok(())
    }

    fn max_message_size(&mut self, bytes: usize) -> PyResult<()> {
        self.max_message_size = Some(bytes);
        Ok(())
    }

    fn max_frame_size(&mut self, bytes: usize) -> PyResult<()> {
        self.max_frame_size = Some(bytes);
        Ok(())
    }

    fn connect_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        self.connect_timeout = Some(timeout_secs);
        Ok(())
    }

    fn handshake_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        self.handshake_timeout = Some(timeout_secs);
        Ok(())
    }

    fn read_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        self.read_timeout = Some(timeout_secs);
        Ok(())
    }

    fn write_timeout(&mut self, timeout_secs: f64) -> PyResult<()> {
        self.write_timeout = Some(timeout_secs);
        Ok(())
    }

    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let headers = self.headers.clone();
        let subprotocols = self.subprotocols.clone();
        let max_message_size = self.max_message_size;
        let max_frame_size = self.max_frame_size;
        let connect_timeout = self.connect_timeout;
        let handshake_timeout = self.handshake_timeout;
        let read_timeout = self.read_timeout;
        let write_timeout = self.write_timeout;

        future_into_py(py, async move {
            let mut builder = client.websocket(url.as_str());
            for (key, value) in headers {
                builder = builder.header(key, value);
            }
            if !subprotocols.is_empty() {
                builder = builder.subprotocols(subprotocols);
            }
            if let Some(bytes) = max_message_size {
                builder = builder.max_message_size(bytes);
            }
            if let Some(bytes) = max_frame_size {
                builder = builder.max_frame_size(bytes);
            }
            if let Some(seconds) = connect_timeout {
                builder = builder.connect_timeout(duration_from_secs(seconds)?);
            }
            if let Some(seconds) = handshake_timeout {
                builder = builder.handshake_timeout(duration_from_secs(seconds)?);
            }
            if let Some(seconds) = read_timeout {
                builder = builder.read_timeout(duration_from_secs(seconds)?);
            }
            if let Some(seconds) = write_timeout {
                builder = builder.write_timeout(duration_from_secs(seconds)?);
            }

            let inner = builder.connect().await.map_err(to_py_websocket_err)?;
            let url = inner.url().to_string();
            let protocol = inner.protocol().map(str::to_string);
            Ok(WebSocket {
                inner: Arc::new(Mutex::new(inner)),
                url,
                protocol,
            })
        })
    }

    fn __repr__(&self) -> String {
        format!("<specter.WebSocketBuilder url={:?}>", self.url)
    }
}

#[pymethods]
impl WebSocket {
    #[getter]
    fn url(&self) -> &str {
        &self.url
    }

    #[getter]
    fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    fn send<'py>(
        &self,
        py: Python<'py>,
        message: PyRef<'_, WebSocketMessage>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let message = message.to_rust()?;
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.send(message).await.map_err(to_py_websocket_err)
        })
    }

    fn send_text<'py>(&self, py: Python<'py>, text: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.send_text(text).await.map_err(to_py_websocket_err)
        })
    }

    fn send_binary<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let data = data.to_vec();
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.send_binary(data).await.map_err(to_py_websocket_err)
        })
    }

    fn send_ping<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
        if data.len() > 125 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "control frame payload exceeds 125 bytes",
            ));
        }
        let inner = self.inner.clone();
        let data = data.to_vec();
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.send(Message::Ping(data.into()))
                .await
                .map_err(to_py_websocket_err)
        })
    }

    fn send_pong<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
        if data.len() > 125 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "control frame payload exceeds 125 bytes",
            ));
        }
        let inner = self.inner.clone();
        let data = data.to_vec();
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.send(Message::Pong(data.into()))
                .await
                .map_err(to_py_websocket_err)
        })
    }

    fn next<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.next()
                .await
                .map(|message| message.map(WebSocketMessage::from_rust))
                .map_err(to_py_websocket_err)
        })
    }

    #[pyo3(signature = (frame = None))]
    fn close<'py>(
        &self,
        py: Python<'py>,
        frame: Option<PyRef<'_, CloseFrame>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let frame = frame.as_deref().map(CloseFrame::to_rust).transpose()?;
        future_into_py(py, async move {
            let mut ws = inner.lock().await;
            ws.close(frame).await.map_err(to_py_websocket_err)
        })
    }

    fn __repr__(&self) -> String {
        format!("<specter.WebSocket url={:?}>", self.url)
    }
}

pub(crate) fn builder_from_client(client: RustClient, url: String) -> WebSocketBuilder {
    WebSocketBuilder::from_client(client, url)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<WebSocketBuilder>()?;
    m.add_class::<WebSocket>()?;
    Ok(())
}

fn duration_from_secs(seconds: f64) -> PyResult<Duration> {
    if seconds.is_sign_negative() || !seconds.is_finite() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "timeout must be a finite non-negative number of seconds",
        ));
    }
    Ok(Duration::from_secs_f64(seconds))
}

fn to_py_websocket_err<E: std::fmt::Display>(error: E) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error.to_string())
}
