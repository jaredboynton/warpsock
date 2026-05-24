#[test]
fn native_h3_driver_schedules_receive_flow_control_updates() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("build_client_receive_flow_control_update_packets"),
        "native H3 driver must automatically send receive-window MAX_DATA/MAX_STREAM_DATA updates"
    );
}

#[test]
fn native_h3_driver_defers_receive_credit_while_streaming_bodies_are_backpressured() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let process_datagram = driver
        .split("async fn process_datagram")
        .nth(1)
        .expect("driver must have process_datagram")
        .split("fn apply_h3_event")
        .next()
        .expect("process_datagram section");
    let event_index = process_datagram
        .find("for event in events")
        .expect("process_datagram must apply H3 events");
    let update_index = process_datagram
        .find("send_receive_flow_control_updates().await?")
        .expect("process_datagram must flush receive-window updates");

    assert!(
        event_index < update_index,
        "native H3 driver must apply response DATA to bounded body queues before advertising more receive credit"
    );
    assert!(
        process_datagram.contains("!self.receive_backpressured()"),
        "native H3 driver must not advertise more receive credit while streaming bodies or tunnels are backpressured"
    );
    assert!(
        driver
            .split("_ = self.body_progress_notify.notified() =>")
            .nth(1)
            .expect("body progress branch")
            .split('}')
            .next()
            .expect("body progress branch body")
            .contains("send_receive_flow_control_updates().await?"),
        "body progress must retry deferred receive-credit updates when user reads open body capacity"
    );
}

#[test]
fn native_h3_tunnel_backpressure_waits_for_all_tunnels_before_pausing_receive() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let tunnel_backpressure = driver
        .split("fn tunnel_inbound_backpressured(&self) -> bool")
        .nth(1)
        .expect("driver must have tunnel_inbound_backpressured")
        .split("fn receive_backpressured")
        .next()
        .expect("tunnel_inbound_backpressured section");

    assert!(
        tunnel_backpressure.contains(".all(|tunnel|"),
        "one slow RFC9220 tunnel must not pause socket reads while a sibling tunnel still has inbound capacity"
    );
    assert!(
        !tunnel_backpressure.contains(".any(|tunnel|"),
        "H3 tunnel receive backpressure must mirror streaming response sibling fairness, not any-tunnel blocking"
    );
}

#[test]
fn native_h3_receive_backpressure_waits_for_all_active_receive_classes() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let receive_backpressure = driver
        .split("fn receive_backpressured(&self) -> bool")
        .nth(1)
        .expect("driver must have receive_backpressured")
        .split("async fn send_preface")
        .next()
        .expect("receive_backpressured section");

    assert!(
        receive_backpressure.contains("has_streaming_responses"),
        "receive backpressure must account for whether streaming response queues are active"
    );
    assert!(
        receive_backpressure.contains("has_tunnels"),
        "receive backpressure must account for whether RFC9220 tunnel queues are active"
    );
    assert!(
        receive_backpressure.contains("streaming_responses_backpressured && tunnels_backpressured"),
        "native H3 receive should pause only when every active response/tunnel receive class is backpressured"
    );
    assert!(
        !receive_backpressure
            .trim()
            .contains("self.streaming_response_body_backpressured() || self.tunnel_inbound_backpressured()"),
        "one blocked receive class must not pause socket reads while another active class still has capacity"
    );
}

#[test]
fn native_h3_driver_flushes_receive_credit_from_consumed_body_bytes() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let body_progress = driver
        .split("_ = self.body_progress_notify.notified() =>")
        .nth(1)
        .expect("body progress branch")
        .split("}")
        .next()
        .expect("body progress branch body");
    let released_body_credits = driver
        .split("async fn apply_released_body_credits")
        .nth(1)
        .expect("driver must have apply_released_body_credits")
        .split("fn apply_released_tunnel_credits")
        .next()
        .expect("apply_released_body_credits section");
    let released_tunnel_credits = driver
        .split("fn apply_released_tunnel_credits")
        .nth(1)
        .expect("driver must have apply_released_tunnel_credits")
        .split("async fn send_stream_cancel")
        .next()
        .expect("apply_released_tunnel_credits section");

    assert!(
        driver.contains("apply_released_body_credits"),
        "native H3 driver must collect public body-consumed bytes before advertising receive credit"
    );
    assert!(
        driver.contains("take_released_recv_bytes"),
        "native H3 driver must read byte-precise H3BodyShared release counters"
    );
    assert!(
        body_progress.contains("apply_released_body_credits().await?"),
        "body progress must apply consumed body-byte credit before flushing receive-window updates"
    );
    assert!(
        released_body_credits.contains("record_client_stream_consumed(stream_id, released as u64)"),
        "body byte release must update QUIC receive credit for the exact stream that the user consumed"
    );
    assert!(
        released_tunnel_credits
            .contains("record_client_stream_consumed(stream_id, released as u64)"),
        "RFC9220 tunnel byte release must update QUIC receive credit for the exact CONNECT stream"
    );
}

#[test]
fn native_h3_connect_wires_client_initial_pto_retransmission() {
    let connection = std::fs::read_to_string("src/transport/h3/connection.rs")
        .expect("native H3 connection source");
    let connect_native = connection
        .split("async fn connect_native")
        .nth(1)
        .expect("native H3 connection must have connect_native")
        .split("fn random_connection_id")
        .next()
        .expect("connect_native section");

    assert!(
        connect_native.contains("record_client_initial_sent_at"),
        "connect_native must record Initial sends so client Initial PTO can arm"
    );
    assert!(
        connect_native.contains("on_loss_detection_timeout")
            && connect_native.contains("retransmit_pto_client_initial_crypto_packets"),
        "connect_native must retransmit client Initial CRYPTO when the loss-detection timer fires"
    );
}

#[test]
fn native_mock_h3_server_schedules_receive_flow_control_updates() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("build_server_receive_flow_control_update_packets"),
        "native mock H3 server must automatically send receive-window MAX_DATA/MAX_STREAM_DATA updates"
    );
}

#[test]
fn native_h3_driver_schedules_lost_application_stream_retransmits() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("retransmit_lost_client_application_stream_packets"),
        "native H3 driver must automatically send lost application STREAM retransmits after ACK/loss updates"
    );
}

#[test]
fn native_h3_driver_retains_connection_close_for_draining_replay() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let driver_fields = driver
        .split("struct NativeH3Driver {")
        .nth(1)
        .expect("driver must have NativeH3Driver")
        .split("struct NativeDriverStreamingResponseState")
        .next()
        .expect("driver field section");
    let send_connection_close = driver
        .split("async fn send_connection_close")
        .nth(1)
        .expect("driver must have send_connection_close")
        .split("async fn send_receive_flow_control_updates")
        .next()
        .expect("send_connection_close section");
    let process_datagram = driver
        .split("async fn process_datagram")
        .nth(1)
        .expect("driver must have process_datagram")
        .split("fn apply_h3_event")
        .next()
        .expect("process_datagram section");
    let drive_loop = driver
        .split("async fn drive_loop")
        .nth(1)
        .expect("driver must have drive_loop")
        .split("fn has_pending_work")
        .next()
        .expect("drive_loop section");

    assert!(
        driver_fields.contains("closing_connection_close_packet: Option<Bytes>"),
        "native H3 driver must retain the protected CONNECTION_CLOSE packet for drain replays"
    );
    assert!(
        send_connection_close
            .contains("self.closing_connection_close_packet = Some(close_packet.clone())"),
        "send_connection_close must remember the protected close packet before entering drain"
    );
    assert!(
        send_connection_close.contains("self.is_draining"),
        "send_connection_close must put the public handle into draining state"
    );
    assert!(
        process_datagram.contains("replay_connection_close().await?"),
        "draining native H3 driver must replay CONNECTION_CLOSE on inbound peer packets instead of processing them"
    );
    assert!(
        drive_loop.matches("run_close_window(&mut buf).await?").count() >= 2,
        "local idle/client-shutdown closes must remain in a bounded drain window and replay CONNECTION_CLOSE before driver exit"
    );
}

#[test]
fn native_h3_driver_requeues_flow_control_blocked_new_stream_commands() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("queue_flow_control_blocked_command"),
        "native H3 driver must queue new request/tunnel commands that hit QUIC stream limits"
    );
    assert!(
        driver.contains("build_client_flow_control_blocked_packet"),
        "native H3 driver must emit DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED when queueing blocked sends"
    );
}

#[test]
fn native_h3_driver_retries_flow_control_blocked_open_stream_data() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");

    assert!(
        driver.contains("flush_pending_tunnel_data"),
        "native H3 driver must retry queued RFC9220 tunnel DATA after MAX_DATA/MAX_STREAM_DATA"
    );
    assert!(
        driver.contains("send_flow_control_blocked_packet"),
        "native H3 driver must emit BLOCKED frames instead of failing open-stream DATA sends"
    );
}

#[test]
fn native_h3_driver_schedules_request_body_and_tunnel_data_fairly() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let scheduler = driver
        .split("struct H3SendScheduler")
        .nth(1)
        .expect("native H3 driver must have a send scheduler")
        .split("struct H3ReleasedReceiveCredit")
        .next()
        .expect("send scheduler section");
    let flush = driver
        .split("async fn flush_scheduled_send_work")
        .nth(1)
        .expect("native H3 driver must flush through the scheduler")
        .split("async fn flush_pending_tunnel_data_once")
        .next()
        .expect("scheduled send flush section");

    assert!(
        scheduler.contains("next_classes"),
        "native H3 scheduler must arbitrate request-body and tunnel DATA classes"
    );
    assert!(
        scheduler.contains("ordered_streams"),
        "native H3 scheduler must rotate streams within each DATA class"
    );
    assert!(
        flush.contains("flush_request_stream_bodies_once")
            && flush.contains("flush_pending_tunnel_data_once"),
        "native H3 driver must route both request-body and tunnel DATA through the fair scheduler"
    );
    assert!(
        driver.contains("data_budget") && driver.contains("record_data_sent"),
        "native H3 sends must use a bounded, adaptive per-turn DATA budget"
    );
}

#[test]
fn native_h3_driver_releases_tunnel_outbound_credit_per_wire_chunk() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let send_tunnel_data = driver
        .split("async fn send_tunnel_data")
        .nth(1)
        .expect("native H3 driver must enqueue tunnel outbound data")
        .split("async fn flush_scheduled_send_work")
        .next()
        .expect("send_tunnel_data section");
    let flush_once = driver
        .split("async fn flush_tunnel_data_once")
        .nth(1)
        .expect("native H3 driver must flush tunnel data")
        .split("async fn flush_request_stream_bodies_once")
        .next()
        .expect("flush_tunnel_data_once section");

    assert!(
        send_tunnel_data.contains("DriverPendingTunnelOutbound::from_outbound"),
        "driver must wrap outbound tunnel chunks with per-outbound byte-credit accounting"
    );
    assert!(
        flush_once.contains("record_chunk_sent"),
        "driver must release tunnel outbound byte credit as each wire chunk is sent"
    );
    assert!(
        flush_once.contains("drain_remaining_credit"),
        "driver must drain any remaining tunnel outbound credit when a queued outbound is fully consumed"
    );
    assert!(
        !flush_once.contains("release_send_bytes(outbound.bytes.len())"),
        "driver must not release a whole queued outbound's credit after only a partial DATA write"
    );
}

#[test]
fn h3_client_slow_path_uses_origin_fair_dispatcher() {
    let h3_client = std::fs::read_to_string("src/transport/h3/mod.rs").expect("h3 module source");
    let pooled_handle = h3_client
        .split("async fn pooled_handle")
        .nth(1)
        .expect("H3Client must have pooled_handle")
        .split("fn pool_key")
        .next()
        .expect("pooled_handle section");
    let dispatcher_index = pooled_handle
        .find("self.dispatcher.acquire")
        .expect("H3Client slow path must acquire an origin-fair dispatcher ticket");
    let connect_index = pooled_handle
        .find("H3Connection::connect")
        .expect("H3Client slow path must establish fresh connections");

    assert!(
        dispatcher_index < connect_index,
        "H3Client must enter origin-fair admission before opening a fresh native H3 connection"
    );
    assert!(
        pooled_handle.contains("OriginKey"),
        "H3Client dispatcher admission must be keyed by origin, not by full fingerprint/pool key"
    );
}

#[test]
fn native_h3_driver_schedules_timer_driven_delayed_application_acks() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let drive_loop = driver
        .split("async fn drive_loop")
        .nth(1)
        .expect("driver must have drive_loop")
        .split("fn has_pending_work")
        .next()
        .expect("drive_loop section");

    assert!(
        drive_loop.contains("client_application_ack_deadline"),
        "native H3 driver must derive a delayed ACK deadline from max_ack_delay_ms"
    );
    assert!(
        drive_loop.contains("send_delayed_application_ack().await?"),
        "native H3 driver must wake on the delayed ACK timer even when ack_eliciting_threshold is not reached"
    );
    assert!(
        driver.contains("ack_delay_exponent"),
        "native H3 delayed ACKs must encode ACK Delay using the configured ack_delay_exponent"
    );
}

#[test]
fn native_h3_driver_treats_pending_delayed_ack_as_pending_work() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let has_pending_work = driver
        .split("fn has_pending_work")
        .nth(1)
        .expect("driver must have has_pending_work")
        .split("fn streaming_response_body_backpressured")
        .next()
        .expect("has_pending_work section");

    assert!(
        has_pending_work.contains("client_application_ack_deadline().is_some()"),
        "native H3 idle handling must not close while a delayed ACK is pending"
    );
    assert!(
        driver.contains("_ = tokio::time::sleep(remaining_idle), if !has_pending_work =>"),
        "native H3 idle sleep must be disabled while delayed ACK or other work is pending"
    );
}

#[test]
fn native_h3_driver_schedules_application_loss_detection_timer() {
    let driver =
        std::fs::read_to_string("src/transport/h3/native_driver.rs").expect("native driver source");
    let drive_loop = driver
        .split("async fn drive_loop")
        .nth(1)
        .expect("driver must have drive_loop")
        .split("fn has_pending_work")
        .next()
        .expect("drive_loop section");
    let has_pending_work = driver
        .split("fn has_pending_work")
        .nth(1)
        .expect("driver must have has_pending_work")
        .split("fn has_outbound_send_work")
        .next()
        .expect("has_pending_work section");

    assert!(
        drive_loop.contains("client_loss_detection_deadline"),
        "native H3 driver must derive a post-handshake QUIC loss-detection deadline"
    );
    assert!(
        drive_loop.contains("handle_loss_detection_timeout().await?"),
        "native H3 driver must wake on the QUIC loss-detection timer"
    );
    assert!(
        has_pending_work.contains("client_loss_detection_deadline().is_some()"),
        "native H3 idle handling must not close while application PTO/recovery work is pending"
    );
    assert!(
        driver.contains("LossDetectionOutcome::Pto {")
            && driver.contains("PacketNumberSpace::Application")
            && driver.contains("retransmit_pto_client_application_stream_packets"),
        "native H3 driver must retransmit application STREAM data on application-space PTO"
    );
}

#[test]
fn native_mock_h3_server_schedules_timer_driven_delayed_application_acks() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("server_application_ack_deadline"),
        "native mock H3 server must derive a delayed ACK deadline from max_ack_delay_ms"
    );
    assert!(
        mock_server.contains("send_delayed_application_ack().await"),
        "native mock H3 server must wake on the delayed ACK timer below ack_eliciting_threshold"
    );
    assert!(
        mock_server.contains("build_server_application_ack_packet_after_or_delay"),
        "native mock H3 server must use threshold-or-delay ACK emission instead of immediate ACKs"
    );
}

#[test]
fn native_h3_same_fixture_schedules_timer_driven_delayed_application_acks() {
    let fixture = std::fs::read_to_string("benches/native_h3_vs_rust_clients/src/main.rs")
        .expect("native H3 same-fixture benchmark source");

    assert!(
        fixture.contains("server_application_ack_deadline"),
        "native H3 same-fixture server must derive a delayed ACK deadline from max_ack_delay_ms"
    );
    assert!(
        fixture.contains("send_delayed_application_ack().await"),
        "native H3 same-fixture server must wake on the delayed ACK timer below ack_eliciting_threshold"
    );
    assert!(
        fixture.contains("build_server_application_ack_packet_after_or_delay"),
        "native H3 same-fixture server must use threshold-or-delay ACK emission instead of immediate ACKs"
    );
}

#[test]
fn native_mock_h3_server_schedules_lost_application_stream_retransmits() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("retransmit_lost_server_application_stream_packets"),
        "native mock H3 server must automatically send lost application STREAM retransmits after ACK/loss updates"
    );
}
