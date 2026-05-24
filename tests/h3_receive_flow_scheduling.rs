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
        process_datagram.contains("if !self.streaming_response_body_backpressured()"),
        "native H3 driver must not advertise more receive credit while every streaming body is backpressured"
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
fn native_mock_h3_server_schedules_lost_application_stream_retransmits() {
    let mock_server = std::fs::read_to_string("tests/helpers/mock_h3_server.rs")
        .expect("native mock H3 server source");

    assert!(
        mock_server.contains("retransmit_lost_server_application_stream_packets"),
        "native mock H3 server must automatically send lost application STREAM retransmits after ACK/loss updates"
    );
}
