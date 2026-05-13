use bytes::Bytes;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_async_runtimes::tokio::future_into_py;
use std::sync::Arc;
use tokio::sync::Mutex;

use ::specter::transport::h3::{H3Tunnel, H3TunnelEvent as RustH3TunnelEvent};
use ::specter::{Client as RustClient, Error as RustError};

const H3_FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "upgrade",
    "host",
    "sec-websocket-key",
    "sec-websocket-accept",
    "sec-websocket-extensions",
];

#[pyclass]
pub struct WebSocketH3Builder {
    client: RustClient,
    url: String,
    headers: Vec<(String, String)>,
}

#[pyclass]
pub struct WebSocketH3Tunnel {
    inner: Arc<Mutex<H3Tunnel>>,
}

#[pyclass]
#[derive(Clone)]
pub struct H3TunnelEvent {
    #[pyo3(get)]
    pub kind: String,
    data: Option<Vec<u8>>,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub last_stream_id: Option<u64>,
}

pub(crate) fn builder_from_client(client: RustClient, url: String) -> WebSocketH3Builder {
    WebSocketH3Builder {
        client,
        url,
        headers: Vec::new(),
    }
}

#[pymethods]
impl WebSocketH3Builder {
    fn header(&mut self, key: String, value: String) -> PyResult<()> {
        reject_h3_forbidden_header(&key)?;
        self.headers.push((key, value));
        Ok(())
    }

    fn headers(&mut self, headers: Vec<(String, String)>) -> PyResult<()> {
        for (key, _) in &headers {
            reject_h3_forbidden_header(key)?;
        }
        self.headers = headers;
        Ok(())
    }

    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let url = self.url.clone();
        let headers = self.headers.clone();

        future_into_py(py, async move {
            let mut builder = client.websocket_h3(url.as_str());
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            let tunnel = builder.open().await.map_err(to_py_err)?;
            Ok(WebSocketH3Tunnel {
                inner: Arc::new(Mutex::new(tunnel)),
            })
        })
    }

    fn __repr__(&self) -> String {
        format!("<specter.WebSocketH3Builder url={}>", self.url)
    }
}

#[pymethods]
impl WebSocketH3Tunnel {
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
                Some(Ok(event)) => Ok(Some(H3TunnelEvent::from(event))),
                Some(Err(err)) => Ok(Some(H3TunnelEvent::from_error(err))),
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
        "<specter.WebSocketH3Tunnel>".to_string()
    }
}

#[pymethods]
impl H3TunnelEvent {
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.data
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    fn __repr__(&self) -> String {
        format!(
            "<specter.H3TunnelEvent kind={} last_stream_id={:?}>",
            self.kind, self.last_stream_id
        )
    }
}

impl From<RustH3TunnelEvent> for H3TunnelEvent {
    fn from(event: RustH3TunnelEvent) -> Self {
        match event {
            RustH3TunnelEvent::Data(bytes) => Self {
                kind: "data".to_string(),
                data: Some(bytes.to_vec()),
                error: None,
                last_stream_id: None,
            },
            RustH3TunnelEvent::EndStream => Self {
                kind: "end_stream".to_string(),
                data: None,
                error: None,
                last_stream_id: None,
            },
            RustH3TunnelEvent::Reset(reason) => Self {
                kind: "reset".to_string(),
                data: None,
                error: Some(reason),
                last_stream_id: None,
            },
            RustH3TunnelEvent::GoAway { id } => Self {
                kind: "goaway".to_string(),
                data: None,
                error: None,
                last_stream_id: Some(id),
            },
        }
    }
}

impl H3TunnelEvent {
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
    m.add_class::<WebSocketH3Builder>()?;
    m.add_class::<WebSocketH3Tunnel>()?;
    m.add_class::<H3TunnelEvent>()?;
    Ok(())
}

fn reject_h3_forbidden_header(key: &str) -> PyResult<()> {
    let normalized = key.trim().to_ascii_lowercase();
    if normalized.starts_with(':')
        || H3_FORBIDDEN_HEADERS
            .iter()
            .any(|blocked| normalized == *blocked)
    {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
            "RFC 9220 raw H3 tunnels do not accept forbidden header: {key}"
        )));
    }
    Ok(())
}

fn to_py_err(error: RustError) -> PyErr {
    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(error.to_string())
}
