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
        mock_server.contains("send_delayed_application_ack().await?"),
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
        fixture.contains("send_delayed_application_ack().await?"),
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
