use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ::specter::{CloseCode as RustCloseCode, CloseFrame as RustCloseFrame, Message};

#[pyclass]
#[derive(Clone)]
pub struct CloseFrame {
    code: u16,
    reason: String,
}

#[pyclass]
#[derive(Clone)]
pub struct WebSocketMessage {
    kind: String,
    text: Option<String>,
    data: Option<Vec<u8>>,
    code: Option<u16>,
    reason: Option<String>,
}

#[pymethods]
impl CloseFrame {
    #[new]
    #[pyo3(signature = (code = 1000, reason = ""))]
    pub fn new(code: u16, reason: &str) -> PyResult<Self> {
        let rust_code = RustCloseCode::from_u16(code).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "invalid WebSocket close code {code}"
            ))
        })?;

        if !rust_code.is_valid_wire_code() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "close code {code} must not be sent on the wire"
            )));
        }

        if reason.len() > 123 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "close reason exceeds 123 bytes",
            ));
        }

        Ok(Self {
            code,
            reason: reason.to_string(),
        })
    }

    #[getter]
    pub fn code(&self) -> u16 {
        self.code
    }

    #[getter]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    fn __repr__(&self) -> String {
        format!(
            "<specter.CloseFrame code={} reason={:?}>",
            self.code, self.reason
        )
    }
}

impl CloseFrame {
    pub(crate) fn to_rust(&self) -> PyResult<RustCloseFrame> {
        let code = RustCloseCode::from_u16(self.code).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "invalid WebSocket close code {}",
                self.code
            ))
        })?;

        Ok(RustCloseFrame {
            code,
            reason: self.reason.clone(),
        })
    }

    pub(crate) fn from_rust(frame: RustCloseFrame) -> Self {
        Self {
            code: frame.code.as_u16(),
            reason: frame.reason,
        }
    }
}

#[pymethods]
impl WebSocketMessage {
    #[new]
    #[pyo3(signature = (kind, text = None, data = None, code = None, reason = None))]
    pub fn new(
        kind: String,
        text: Option<String>,
        data: Option<&[u8]>,
        code: Option<u16>,
        reason: Option<String>,
    ) -> PyResult<Self> {
        match kind.as_str() {
            "text" => Ok(Self::text(text.unwrap_or_default())),
            "binary" => Ok(Self {
                kind,
                text: None,
                data: Some(data.unwrap_or_default().to_vec()),
                code: None,
                reason: None,
            }),
            "ping" | "pong" => {
                let payload = data.unwrap_or_default();
                if payload.len() > 125 {
                    return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                        "control frame payload exceeds 125 bytes",
                    ));
                }
                Ok(Self {
                    kind,
                    text: None,
                    data: Some(payload.to_vec()),
                    code: None,
                    reason: None,
                })
            }
            "close" => {
                let frame = match code {
                    Some(code) => Some(CloseFrame::new(code, reason.as_deref().unwrap_or(""))?),
                    None => None,
                };
                Ok(Self::close(frame.as_ref()))
            }
            _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "unsupported WebSocket message kind {kind:?}"
            ))),
        }
    }

    #[getter]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[getter]
    #[pyo3(name = "text")]
    pub fn get_text(&self) -> Option<&str> {
        self.text.as_deref()
    }

    #[getter]
    pub fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.data
            .as_ref()
            .map(|data| PyBytes::new(py, data.as_slice()))
    }

    #[getter]
    pub fn code(&self) -> Option<u16> {
        self.code
    }

    #[getter]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    fn __repr__(&self) -> String {
        format!("<specter.WebSocketMessage kind={:?}>", self.kind)
    }
}

impl WebSocketMessage {
    pub(crate) fn text(value: String) -> Self {
        Self {
            kind: "text".to_string(),
            text: Some(value),
            data: None,
            code: None,
            reason: None,
        }
    }

    pub(crate) fn close(frame: Option<&CloseFrame>) -> Self {
        match frame {
            Some(frame) => Self {
                kind: "close".to_string(),
                text: None,
                data: None,
                code: Some(frame.code),
                reason: Some(frame.reason.clone()),
            },
            None => Self {
                kind: "close".to_string(),
                text: None,
                data: None,
                code: None,
                reason: None,
            },
        }
    }

    pub(crate) fn from_rust(message: Message) -> Self {
        match message {
            Message::Text(text) => Self::text(text),
            Message::Binary(data) => Self {
                kind: "binary".to_string(),
                text: None,
                data: Some(data.to_vec()),
                code: None,
                reason: None,
            },
            Message::Ping(data) => Self {
                kind: "ping".to_string(),
                text: None,
                data: Some(data.to_vec()),
                code: None,
                reason: None,
            },
            Message::Pong(data) => Self {
                kind: "pong".to_string(),
                text: None,
                data: Some(data.to_vec()),
                code: None,
                reason: None,
            },
            Message::Close(frame) => match frame {
                Some(frame) => {
                    let frame = CloseFrame::from_rust(frame);
                    Self::close(Some(&frame))
                }
                None => Self::close(None),
            },
        }
    }

    pub(crate) fn to_rust(&self) -> PyResult<Message> {
        match self.kind.as_str() {
            "text" => Ok(Message::Text(self.text.clone().unwrap_or_default())),
            "binary" => Ok(Message::Binary(
                self.data.clone().unwrap_or_default().into(),
            )),
            "ping" => Ok(Message::Ping(self.data.clone().unwrap_or_default().into())),
            "pong" => Ok(Message::Pong(self.data.clone().unwrap_or_default().into())),
            "close" => {
                let frame = match self.code {
                    Some(code) => Some(
                        CloseFrame::new(code, self.reason.as_deref().unwrap_or_default())?
                            .to_rust()?,
                    ),
                    None => None,
                };
                Ok(Message::Close(frame))
            }
            kind => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "unsupported WebSocket message kind {kind:?}"
            ))),
        }
    }
}

fn valid_close_code(code: u16) -> bool {
    RustCloseCode::from_u16(code)
        .map(RustCloseCode::is_valid_wire_code)
        .unwrap_or(false)
}

#[pyfunction]
pub fn is_valid_close_code(code: u16) -> bool {
    valid_close_code(code)
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CloseFrame>()?;
    m.add_class::<WebSocketMessage>()?;
    m.add("CLOSE_NORMAL", 1000_u16)?;
    m.add("CLOSE_GOING_AWAY", 1001_u16)?;
    m.add("CLOSE_PROTOCOL_ERROR", 1002_u16)?;
    m.add("CLOSE_UNSUPPORTED", 1003_u16)?;
    m.add("CLOSE_NO_STATUS", 1005_u16)?;
    m.add("CLOSE_ABNORMAL", 1006_u16)?;
    m.add("CLOSE_INVALID_PAYLOAD", 1007_u16)?;
    m.add("CLOSE_POLICY_VIOLATION", 1008_u16)?;
    m.add("CLOSE_MESSAGE_TOO_BIG", 1009_u16)?;
    m.add("CLOSE_MANDATORY_EXTENSION", 1010_u16)?;
    m.add("CLOSE_INTERNAL_ERROR", 1011_u16)?;
    m.add("CLOSE_TLS_ERROR", 1015_u16)?;
    m.add_function(wrap_pyfunction!(is_valid_close_code, m)?)?;
    Ok(())
}
