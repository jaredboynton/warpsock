use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;
use tokio::sync::Mutex;

use ::specter::transport::h2::{H2Tunnel, H2TunnelEvent as RustH2TunnelEvent};
use ::specter::{Client as RustClient, Error as RustError};

const H1_WEBSOCKET_ONLY_HEADERS: &[&str] = &[
    "sec-websocket-key",
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-version",
    "connection",
    "upgrade",
];

#[pyclass]
pub struct WebSocketH2Builder {
    client: RustClient,
    url: String,
    headers: Vec<(String, String)>,
}

#[pyclass]
pub struct WebSocketH2Tunnel {
    inner: Arc<Mutex<H2Tunnel>>,
}

#[pyclass]
#[derive(Clone)]
pub struct H2TunnelEvent {
    #[pyo3(get)]
    pub kind: String,
    data: Option<Vec<u8>>,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub last_stream_id: Option<u32>,
}

pub(crate) fn builder_from_client(client: RustClient, url: String) -> WebSocketH2Builder {
    WebSocketH2Builder {
        client,
        url,
        headers: Vec::new(),
    }
}

#[pymethods]
impl WebSocketH2Builder {
    fn header(&mut self, key: String, value: String) -> PyResult<()> {
        reject_h1_websocket_header(&key)?;
        self.headers.push((key, value));
        Ok(())
    }

    fn headers(&mut self, headers: Vec<(String, String)>) -> PyResult<()> {
        for (key, _) in &headers {
            reject_h1_websocket_header(key)?;
        }
        self.headers = headers;
        Ok(())
    }

    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let headers = self.headers.clone();

        future_into_py(py, async move {
            let mut builder = client.websocket_h2(url.as_str());
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            let tunnel = builder.open().await.map_err(to_py_err)?;
            Ok(WebSocketH2Tunnel {
                inner: Arc::new(Mutex::new(tunnel)),
            })
        })
    }

    fn __repr__(&self) -> String {
        format!("<specter.WebSocketH2Builder url={}>", self.url)
    }
}

#[pymethods]
impl WebSocketH2Tunnel {
    #[pyo3(signature = (data, end_stream=None))]
    fn send_bytes<'py>(
        &self,
        py: Python<'py>,
        data: &[u8],
        end_stream: Option<bool>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let tunnel = self.inner.clone();
        let bytes = Bytes::copy_from_slice(data);
        let end_stream = end_stream.unwrap_or(false);

        future_into_py(py, async move {
            tunnel
                .lock()
                .await
                .send_bytes(bytes, end_stream)
                .await
                .map_err(to_py_err)
        })
    }

    fn recv_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let tunnel = self.inner.clone();

        future_into_py(py, async move {
            let bytes = tunnel
                .lock()
                .await
                .recv_bytes()
                .await
                .transpose()
                .map_err(to_py_err)?;

            Python::with_gil(|py| match bytes {
                Some(bytes) => Ok(Some(PyBytes::new(py, bytes.as_ref()).unbind())),
                None => Ok(None),
            })
        })
    }

    fn recv_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let tunnel = self.inner.clone();

        future_into_py(py, async move {
            let event = tunnel.lock().await.recv_event().await;
            match event {
                Some(Ok(event)) => Ok(Some(H2TunnelEvent::from(event))),
                Some(Err(err)) => Ok(Some(H2TunnelEvent::from_error(err))),
                None => Ok(None),
            }
        })
    }

    fn close_send<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let tunnel = self.inner.clone();

        future_into_py(py, async move {
            tunnel.lock().await.close_send().await.map_err(to_py_err)
        })
    }

    fn __repr__(&self) -> String {
        "<specter.WebSocketH2Tunnel>".to_string()
    }
}

#[pymethods]
impl H2TunnelEvent {
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.data
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    fn __repr__(&self) -> String {
        format!(
            "<specter.H2TunnelEvent kind={} last_stream_id={:?}>",
            self.kind, self.last_stream_id
        )
    }
}

impl From<RustH2TunnelEvent> for H2TunnelEvent {
    fn from(event: RustH2TunnelEvent) -> Self {
        match event {
            RustH2TunnelEvent::Data(bytes) => Self {
                kind: "data".to_string(),
                data: Some(bytes.to_vec()),
                error: None,
                last_stream_id: None,
            },
            RustH2TunnelEvent::EndStream => Self {
                kind: "end_stream".to_string(),
                data: None,
                error: None,
                last_stream_id: None,
            },
            RustH2TunnelEvent::Reset(reason) => Self {
                kind: "reset".to_string(),
                data: None,
                error: Some(reason),
                last_stream_id: None,
            },
            RustH2TunnelEvent::GoAway { last_stream_id } => Self {
                kind: "goaway".to_string(),
                data: None,
                error: None,
                last_stream_id: Some(last_stream_id),
            },
        }
    }
}

impl H2TunnelEvent {
    fn from_error(error: RustError) -> Self {
        Self {
            kind: "error".to_string(),
            data: None,
            error: Some(error.to_string()),
            last_stream_id: None,
        }
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<WebSocketH2Builder>()?;
    m.add_class::<WebSocketH2Tunnel>()?;
    m.add_class::<H2TunnelEvent>()?;
    Ok(())
}

fn reject_h1_websocket_header(key: &str) -> PyResult<()> {
    let normalized = key.trim().to_ascii_lowercase();
    if H1_WEBSOCKET_ONLY_HEADERS
        .iter()
        .any(|blocked| normalized == *blocked)
    {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "RFC 8441 raw H2 tunnels do not accept H1 WebSocket header: {key}"
        )));
    }
    Ok(())
}

fn to_py_err(error: RustError) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error.to_string())
}
