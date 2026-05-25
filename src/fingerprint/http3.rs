//! HTTP/3 and QUIC fingerprint configuration.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Http3Fingerprint {
    pub alpn_protocols: Vec<Vec<u8>>,
    pub transport: QuicTransportParams,
    pub settings: H3Settings,
    pub stream: H3StreamFingerprint,
}

impl Default for Http3Fingerprint {
    fn default() -> Self {
        Self::chrome()
    }
}

impl Http3Fingerprint {
    pub fn chrome() -> Self {
        Self {
            alpn_protocols: vec![b"h3".to_vec()],
            transport: QuicTransportParams::chrome(),
            settings: H3Settings::chrome(),
            stream: H3StreamFingerprint::chrome(),
        }
    }

    pub fn firefox() -> Self {
        Self {
            alpn_protocols: vec![b"h3".to_vec()],
            transport: QuicTransportParams::firefox(),
            settings: H3Settings::firefox(),
            stream: H3StreamFingerprint::firefox(),
        }
    }

    pub fn pool_key_string(&self) -> String {
        let alpn = self
            .alpn_protocols
            .iter()
            .map(|proto| String::from_utf8_lossy(proto).into_owned())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "alpn={alpn};transport={};settings={};stream={}",
            self.transport.pool_key_string(),
            self.settings.pool_key_string(),
            self.stream.pool_key_string(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawQuicTransportParameter {
    pub id: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RawQuicTransportParameterConnectionId {
    OriginalDestination,
    InitialSource,
    RetrySource,
}

impl RawQuicTransportParameter {
    const ORIGINAL_DESTINATION_CONNECTION_ID_ID: u64 = 0x00;
    const INITIAL_SOURCE_CONNECTION_ID_ID: u64 = 0x0f;
    const RETRY_SOURCE_CONNECTION_ID_ID: u64 = 0x10;
    const ORIGINAL_DESTINATION_CONNECTION_ID_PLACEHOLDER: &'static [u8] =
        b"$specter:original_destination_connection_id";
    const INITIAL_SOURCE_CONNECTION_ID_PLACEHOLDER: &'static [u8] =
        b"$specter:initial_source_connection_id";
    const RETRY_SOURCE_CONNECTION_ID_PLACEHOLDER: &'static [u8] =
        b"$specter:retry_source_connection_id";

    pub fn original_destination_connection_id() -> Self {
        Self {
            id: Self::ORIGINAL_DESTINATION_CONNECTION_ID_ID,
            value: Self::ORIGINAL_DESTINATION_CONNECTION_ID_PLACEHOLDER.to_vec(),
        }
    }

    pub fn initial_source_connection_id() -> Self {
        Self {
            id: Self::INITIAL_SOURCE_CONNECTION_ID_ID,
            value: Self::INITIAL_SOURCE_CONNECTION_ID_PLACEHOLDER.to_vec(),
        }
    }

    pub fn retry_source_connection_id() -> Self {
        Self {
            id: Self::RETRY_SOURCE_CONNECTION_ID_ID,
            value: Self::RETRY_SOURCE_CONNECTION_ID_PLACEHOLDER.to_vec(),
        }
    }

    pub(crate) fn connection_id_placeholder(
        &self,
    ) -> Option<RawQuicTransportParameterConnectionId> {
        match (self.id, self.value.as_slice()) {
            (
                Self::ORIGINAL_DESTINATION_CONNECTION_ID_ID,
                Self::ORIGINAL_DESTINATION_CONNECTION_ID_PLACEHOLDER,
            ) => Some(RawQuicTransportParameterConnectionId::OriginalDestination),
            (
                Self::INITIAL_SOURCE_CONNECTION_ID_ID,
                Self::INITIAL_SOURCE_CONNECTION_ID_PLACEHOLDER,
            ) => Some(RawQuicTransportParameterConnectionId::InitialSource),
            (Self::RETRY_SOURCE_CONNECTION_ID_ID, Self::RETRY_SOURCE_CONNECTION_ID_PLACEHOLDER) => {
                Some(RawQuicTransportParameterConnectionId::RetrySource)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicEcnCodepoint {
    Ect0,
    Ect1,
}

impl QuicEcnCodepoint {
    pub fn ip_tos_bits(self) -> u32 {
        match self {
            Self::Ect0 => 0b10,
            Self::Ect1 => 0b01,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuicTransportParams {
    pub max_idle_timeout_ms: u64,
    pub max_recv_udp_payload_size: usize,
    pub max_send_udp_payload_size: usize,
    pub initial_datagram_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay_ms: u64,
    pub ack_eliciting_threshold: usize,
    pub active_connection_id_limit: u64,
    pub disable_active_migration: bool,
    pub disable_dcid_reuse: bool,
    pub grease: bool,
    pub additional_transport_parameters: Vec<(u64, Vec<u8>)>,
    pub raw_ordered_transport_parameters: Option<Vec<RawQuicTransportParameter>>,
    pub max_datagram_frame_size: Option<u64>,
    pub destination_connection_id_len: usize,
    pub source_connection_id_len: usize,
    pub max_amplification_factor: usize,
    pub initial_rtt_ms: u64,
    pub initial_congestion_window_packets: usize,
    pub pacing_enabled: bool,
    pub max_pacing_rate: Option<u64>,
    pub relaxed_loss_threshold: bool,
    pub max_connection_window: u64,
    pub max_stream_window: u64,
    pub ecn_codepoint: Option<QuicEcnCodepoint>,
}

impl QuicTransportParams {
    pub fn chrome() -> Self {
        Self {
            max_idle_timeout_ms: 30_000,
            max_recv_udp_payload_size: 65_535,
            max_send_udp_payload_size: 1350,
            initial_datagram_size: 1200,
            initial_max_data: 15_663_105,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            ack_eliciting_threshold: 10,
            active_connection_id_limit: 2,
            disable_active_migration: true,
            disable_dcid_reuse: false,
            grease: true,
            additional_transport_parameters: Vec::new(),
            raw_ordered_transport_parameters: None,
            max_datagram_frame_size: None,
            destination_connection_id_len: 16,
            source_connection_id_len: 16,
            max_amplification_factor: 3,
            initial_rtt_ms: 333,
            initial_congestion_window_packets: 10,
            pacing_enabled: true,
            max_pacing_rate: None,
            relaxed_loss_threshold: false,
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 16 * 1024 * 1024,
            ecn_codepoint: None,
        }
    }

    pub fn firefox() -> Self {
        Self {
            grease: false,
            max_ack_delay_ms: 20,
            ack_eliciting_threshold: 2,
            initial_max_stream_data_bidi_local: 4 * 1024 * 1024,
            initial_max_stream_data_bidi_remote: 4 * 1024 * 1024,
            initial_max_stream_data_uni: 4 * 1024 * 1024,
            ..Self::chrome()
        }
    }

    pub fn pool_key_string(&self) -> String {
        let additional_transport_parameters = self
            .additional_transport_parameters
            .iter()
            .map(|(key, value)| {
                let value_hex = value
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                format!("{key}:{value_hex}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let raw_ordered_transport_parameters = self
            .raw_ordered_transport_parameters
            .as_ref()
            .map(|parameters| {
                parameters
                    .iter()
                    .map(|parameter| {
                        let value_hex = parameter
                            .value
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>();
                        format!("{}:{value_hex}", parameter.id)
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|| "none".to_string());
        format!(
            "idle={};recv_udp={};send_udp={};initial_dgram={};max_data={};bidi_local={};bidi_remote={};uni_data={};bidi_streams={};uni_streams={};ack_exp={};ack_delay={};ack_threshold={};cid_limit={};disable_migration={};disable_dcid_reuse={};grease={};additional={additional_transport_parameters};raw_ordered={raw_ordered_transport_parameters};max_datagram={:?};dcid_len={};scid_len={};amp={};rtt={};cwnd={};pacing={};max_pacing={:?};relaxed_loss={};conn_win={};stream_win={};ecn={:?}",
            self.max_idle_timeout_ms,
            self.max_recv_udp_payload_size,
            self.max_send_udp_payload_size,
            self.initial_datagram_size,
            self.initial_max_data,
            self.initial_max_stream_data_bidi_local,
            self.initial_max_stream_data_bidi_remote,
            self.initial_max_stream_data_uni,
            self.initial_max_streams_bidi,
            self.initial_max_streams_uni,
            self.ack_delay_exponent,
            self.max_ack_delay_ms,
            self.ack_eliciting_threshold,
            self.active_connection_id_limit,
            self.disable_active_migration,
            self.disable_dcid_reuse,
            self.grease,
            self.max_datagram_frame_size,
            self.destination_connection_id_len,
            self.source_connection_id_len,
            self.max_amplification_factor,
            self.initial_rtt_ms,
            self.initial_congestion_window_packets,
            self.pacing_enabled,
            self.max_pacing_rate,
            self.relaxed_loss_threshold,
            self.max_connection_window,
            self.max_stream_window,
            self.ecn_codepoint,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct H3Settings {
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
    pub max_field_section_size: Option<u64>,
    pub enable_extended_connect: bool,
    pub additional_settings: Vec<(u64, u64)>,
    pub raw_ordered_settings: Option<Vec<(u64, u64)>>,
}

impl H3Settings {
    pub fn chrome() -> Self {
        Self {
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
            max_field_section_size: None,
            enable_extended_connect: true,
            additional_settings: Vec::new(),
            raw_ordered_settings: None,
        }
    }

    pub fn firefox() -> Self {
        Self {
            enable_extended_connect: true,
            ..Self::chrome()
        }
    }

    pub fn pool_key_string(&self) -> String {
        let additional = self
            .additional_settings
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join(",");
        let raw_ordered = self
            .raw_ordered_settings
            .as_ref()
            .map(|settings| {
                settings
                    .iter()
                    .map(|(key, value)| format!("{key}:{value}"))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        format!(
            "qpack_table={:?};qpack_blocked={:?};max_field={:?};extended_connect={};additional={additional};raw_ordered={raw_ordered}",
            self.qpack_max_table_capacity,
            self.qpack_blocked_streams,
            self.max_field_section_size,
            self.enable_extended_connect,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QpackHeaderBlockStrategy {
    StaticThenLiteral,
    LiteralOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QpackStringEncodingStrategy {
    Plain,
    Huffman,
    HuffmanIfSmaller,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct H3StreamFingerprint {
    pub open_control_stream_first: bool,
    pub open_qpack_encoder_before_decoder: bool,
    pub send_grease_stream: bool,
    pub send_grease_frames: bool,
    pub qpack_encoder_stream_payload: Vec<u8>,
    pub qpack_decoder_stream_payload: Vec<u8>,
    pub request_header_block_strategy: QpackHeaderBlockStrategy,
    pub request_string_encoding: QpackStringEncodingStrategy,
}

impl H3StreamFingerprint {
    pub fn chrome() -> Self {
        Self {
            open_control_stream_first: true,
            open_qpack_encoder_before_decoder: true,
            send_grease_stream: true,
            send_grease_frames: true,
            qpack_encoder_stream_payload: Vec::new(),
            qpack_decoder_stream_payload: Vec::new(),
            request_header_block_strategy: QpackHeaderBlockStrategy::StaticThenLiteral,
            request_string_encoding: QpackStringEncodingStrategy::Plain,
        }
    }

    pub fn firefox() -> Self {
        Self {
            send_grease_stream: false,
            send_grease_frames: false,
            ..Self::chrome()
        }
    }

    pub fn pool_key_string(&self) -> String {
        let qpack_encoder = self
            .qpack_encoder_stream_payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let qpack_decoder = self
            .qpack_decoder_stream_payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "control_first={};qpack_encoder_first={};grease_stream={};grease_frames={};qpack_encoder={qpack_encoder};qpack_decoder={qpack_decoder};request_header_strategy={:?};request_string_encoding={:?}",
            self.open_control_stream_first,
            self.open_qpack_encoder_before_decoder,
            self.send_grease_stream,
            self.send_grease_frames,
            self.request_header_block_strategy,
            self.request_string_encoding,
        )
    }
}
