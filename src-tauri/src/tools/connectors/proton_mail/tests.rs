use super::config::ConnectionSecurity;
use super::message::{
    destination_arg, mailbox_list, parse_full_message, parse_message_summary, seen_flag_query,
    truncate_chars, uid_set_arg, validate_outgoing_body, ReadFormat,
};
use super::transport::AcceptBridgeCertificate;
use super::*;
use crate::tools::auth::InMemorySecrets;
use mail_parser::MessageParser;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

struct StoredConfig(Option<ProtonMailConfig>);

impl ConfigFile for StoredConfig {
    fn load(&self) -> Result<Option<ProtonMailConfig>, String> {
        Ok(self.0.clone())
    }

    fn save(&self, _config: &ProtonMailConfig) -> Result<(), String> {
        Ok(())
    }

    fn delete(&self) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn mail_read_only_access_excludes_changing_and_sending() {
    let tools = connector(None, None).tools();
    assert_eq!(tools.len(), 7);
    for tool in tools {
        let changes = matches!(
            tool.name.as_str(),
            "mark_read" | "move_messages" | "send_email"
        );
        assert_eq!(tool.read_only, Some(!changes), "{}", tool.name);
    }
}

#[test]
fn moving_and_sending_ask_while_marking_as_read_runs_on_its_own() {
    let policy = |name: &str| {
        connector(None, None)
            .tools()
            .into_iter()
            .find(|tool| tool.name == name)
            .map(|tool| tool.policy)
    };
    assert_eq!(policy("mark_read"), Some(ToolPolicy::AutoApprove));
    assert_eq!(policy("move_messages"), Some(ToolPolicy::Ask));
    assert_eq!(policy("send_email"), Some(ToolPolicy::Ask));
}

#[test]
fn uid_sets_are_bounded_deduplicated_and_positive() {
    assert_eq!(uid_set_arg(&json!({"uids": [7, 3, 7, 12]})).unwrap(), "3,7,12");
    assert!(uid_set_arg(&json!({})).is_err());
    assert!(uid_set_arg(&json!({"uids": []})).is_err());
    assert!(uid_set_arg(&json!({"uids": [0]})).is_err());
    assert!(uid_set_arg(&json!({"uids": [-1]})).is_err());
    assert!(uid_set_arg(&json!({"uids": ["5"]})).is_err());
    assert!(uid_set_arg(&json!({"uids": [u64::from(u32::MAX) + 1]})).is_err());
    let too_many: Vec<usize> = (1..=MAX_MESSAGES + 1).collect();
    assert!(uid_set_arg(&json!({ "uids": too_many })).is_err());
    let at_limit: Vec<usize> = (1..=MAX_MESSAGES).collect();
    assert!(uid_set_arg(&json!({ "uids": at_limit })).is_ok());
}

#[test]
fn marking_as_read_adds_the_seen_flag_unless_told_otherwise() {
    assert_eq!(seen_flag_query(&json!({})).unwrap(), "+FLAGS.SILENT (\\Seen)");
    assert_eq!(
        seen_flag_query(&json!({"read": true})).unwrap(),
        "+FLAGS.SILENT (\\Seen)"
    );
    assert_eq!(
        seen_flag_query(&json!({"read": false})).unwrap(),
        "-FLAGS.SILENT (\\Seen)"
    );
    assert!(seen_flag_query(&json!({"read": "no"})).is_err());
}

#[test]
fn a_move_needs_a_different_single_line_destination() {
    assert_eq!(
        destination_arg(&json!({"destination": "Folders/Invoices"}), "INBOX").unwrap(),
        "Folders/Invoices"
    );
    assert!(destination_arg(&json!({}), "INBOX").is_err());
    assert!(destination_arg(&json!({"destination": ""}), "INBOX").is_err());
    assert!(destination_arg(&json!({"destination": "INBOX"}), "INBOX").is_err());
    assert!(destination_arg(&json!({"destination": "Archive\r\nA1 LOGOUT"}), "INBOX").is_err());
}

fn bridge_config() -> ProtonMailConfig {
    ProtonMailConfig {
        imap_port: 1143,
        smtp_port: 1025,
        username: "user@proton.me".into(),
        imap_security: ConnectionSecurity::StartTls,
        smtp_security: ConnectionSecurity::StartTls,
    }
}

fn connector(config: Option<ProtonMailConfig>, password: Option<&str>) -> ProtonMailConnector {
    let secrets = match password {
        Some(password) => InMemorySecrets::with(&[(SECRET_NAME, password)]),
        None => InMemorySecrets::empty(),
    };
    let credentials = match password {
        Some(_) => CredentialState::Present,
        None => CredentialState::Absent,
    };
    ProtonMailConnector::new(Box::new(StoredConfig(config)), secrets, credentials)
}

#[test]
fn bridge_settings_without_a_password_are_not_enough_to_be_ready() {
    assert_eq!(
        connector(Some(bridge_config()), None).readiness(),
        Readiness::blocked("Not connected")
    );
    assert_eq!(
        connector(None, Some("bridge-password")).readiness(),
        Readiness::blocked("Not connected")
    );
}

#[tokio::test]
async fn a_configured_connector_is_ready_before_bridge_is_ever_contacted() {
    let connector = connector(Some(bridge_config()), Some("bridge-password"));

    assert_eq!(
        connector.readiness(),
        Readiness::Ready,
        "readiness must not depend on whether Bridge is running"
    );
    assert!(
        connector.as_session().is_none(),
        "each call opens its own IMAP connection, so there is no session to hold"
    );
}

#[tokio::test]
async fn forgetting_clears_both_the_password_and_the_bridge_settings() {
    let connector = connector(Some(bridge_config()), Some("bridge-password"));

    connector.forget().await.expect("forget should succeed");

    assert_eq!(connector.readiness(), Readiness::blocked("Not connected"));
}

#[test]
fn a_non_ascii_search_declares_the_utf8_charset() {
    let query = build_search_query(&json!({ "subject": "Rückfrage" })).unwrap();
    assert_eq!(query, "CHARSET UTF-8 SUBJECT \"Rückfrage\"");
}

#[test]
fn an_ascii_search_does_not_declare_a_charset() {
    let query = build_search_query(&json!({ "subject": "Question", "unread": true })).unwrap();
    assert_eq!(query, "SUBJECT \"Question\" UNSEEN");
}

#[test]
fn config_round_trips_without_a_password() {
    let config = ProtonMailConfig {
        imap_port: 1143,
        smtp_port: 1025,
        username: "bridge-user".into(),
        imap_security: ConnectionSecurity::StartTls,
        smtp_security: ConnectionSecurity::Tls,
    };
    let json = serde_json::to_string(&config).unwrap();
    assert!(!json.contains("password"));
    assert_eq!(
        serde_json::from_str::<ProtonMailConfig>(&json).unwrap(),
        config
    );
}

#[test]
fn search_is_structured_escaped_and_date_checked() {
    let input = json!({
        "from": "alice@example.com",
        "subject": "a \"quote\"",
        "since": "2026-09-01",
        "unread": true
    });
    assert_eq!(
        build_search_query(&input).unwrap(),
        "FROM \"alice@example.com\" SUBJECT \"a \\\"quote\\\"\" SINCE 01-Sep-2026 UNSEEN"
    );
    assert!(build_search_query(&json!({"text": "bad\r\nUID SEARCH ALL"})).is_err());
    assert!(build_search_query(&json!({"since": "09/01/2026"})).is_err());
}

#[test]
fn mime_message_is_converted_to_bounded_plain_text() {
    let raw = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Hello\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello Bob";
    let message = MessageParser::default().parse(raw).unwrap();
    assert_eq!(message.subject(), Some("Hello"));
    assert_eq!(message.body_text(0).as_deref(), Some("Hello Bob"));
    assert_eq!(truncate_chars("abcdef", 3), "abc");
}

#[test]
fn html_email_is_parsed_and_read_formats_are_validated() {
    let raw = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: HTML\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><strong>Hello</strong></body></html>";
    let message = MessageParser::default().parse(raw).unwrap();
    assert!(!message.html_body.is_empty());
    assert!(message
        .body_html(0)
        .unwrap()
        .contains("<strong>Hello</strong>"));
    assert!(matches!(
        read_format_arg(&json!({"format": "both"})).unwrap(),
        ReadFormat::Both
    ));
    assert!(read_format_arg(&json!({"format": "markdown"})).is_err());
}

#[test]
fn a_message_cut_by_the_fetch_limit_is_reported_as_truncated() {
    let attachment = "QUJDRA==".repeat(MAX_MESSAGE_BYTES / 8);
    let raw = format!(
        "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Big\r\n\
             Content-Type: multipart/mixed; boundary=sep\r\n\r\n\
             --sep\r\nContent-Type: text/plain\r\n\r\nShort body.\r\n\
             --sep\r\nContent-Type: application/octet-stream\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n{attachment}\r\n--sep--\r\n"
    );
    let cut = &raw.as_bytes()[..MAX_MESSAGE_BYTES];

    let value = parse_full_message(cut, Some(7), Some(raw.len() as u32), None, ReadFormat::Text)
        .expect("truncated multipart should still parse into a result");
    assert_eq!(value["raw_truncated"], true);
    assert_eq!(
        value["truncated"], true,
        "a body cut mid-MIME must not be reported as complete"
    );
    assert!(
        value["body"].as_str().unwrap().chars().count() < MAX_BODY_CHARS,
        "the decoded text is short, so only the raw cut can flag truncation"
    );
}

#[test]
fn a_complete_message_is_not_reported_as_truncated() {
    let raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Small\r\n\r\nHello.";
    let value =
        parse_full_message(raw, Some(8), Some(raw.len() as u32), None, ReadFormat::Both).unwrap();
    assert_eq!(value["raw_truncated"], false);
    assert_eq!(value["text_truncated"], false);
    assert_eq!(value["html_truncated"], false);
}

#[test]
fn outgoing_html_has_plain_text_fallback() {
    let message = build_outgoing_message(
        "sender@proton.me",
        &json!({
            "to": ["recipient@example.com"],
            "subject": "HTML test",
            "body": "Hello",
            "html_body": "<p><strong>Hello</strong></p>"
        }),
    )
    .unwrap();
    let encoded = String::from_utf8(message.formatted()).unwrap();
    assert!(encoded.contains("multipart/alternative"));
    assert!(encoded.contains("text/plain"));
    assert!(encoded.contains("text/html"));
}

#[test]
fn outgoing_bodies_are_bounded() {
    assert!(validate_outgoing_body(&"x".repeat(MAX_BODY_CHARS + 1), None).is_err());
    assert!(validate_outgoing_body("fallback", Some(&"x".repeat(MAX_HTML_CHARS + 1))).is_err());
}

#[test]
fn fetched_headers_produce_message_summaries() {
    let header = b"From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nSubject: Latest update\r\nDate: Mon, 7 Sep 2026 10:00:00 +0200\r\nMessage-ID: <latest@example.com>\r\n\r\n";
    let received_at = chrono::DateTime::parse_from_rfc3339("2026-09-07T10:05:00+02:00").unwrap();
    let (_, summary) = parse_message_summary(
        header,
        Some(42),
        Some(1234),
        Some(received_at),
        vec!["Seen".into()],
    )
    .unwrap();
    assert_eq!(summary["uid"], 42);
    assert_eq!(summary["subject"], "Latest update");
    assert_eq!(summary["from"][0]["address"], "alice@example.com");
    assert_eq!(summary["received_at"], "2026-09-07T10:05:00+02:00");
}

#[test]
fn recent_list_defaults_to_a_bounded_window() {
    assert_eq!(recent_days_arg(&json!({})).unwrap(), DEFAULT_RECENT_DAYS);
    assert!(recent_since_query(DEFAULT_RECENT_DAYS).starts_with("SINCE "));
    assert!(recent_days_arg(&json!({"days": 0})).is_err());
    assert!(recent_days_arg(&json!({"days": MAX_RECENT_DAYS + 1})).is_err());
}

#[test]
fn send_is_approval_gated() {
    let definition = ToolDefinition {
        policy: ToolPolicy::Ask,
        ..tool("send_email", "Send email", "Send.", send_schema())
    };
    assert_eq!(definition.policy, ToolPolicy::Ask);
}

#[test]
fn recipient_lists_are_validated() {
    assert_eq!(
        mailbox_list(&json!({"to": ["Alice <alice@example.com>"]}), "to", true)
            .unwrap()
            .len(),
        1
    );
    assert!(mailbox_list(&json!({"to": []}), "to", true).is_err());
    assert!(mailbox_list(&json!({"to": ["not an address"]}), "to", true).is_err());
}

#[tokio::test]
async fn starttls_is_required_before_credentials_are_sent() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"* OK test bridge\r\n").await.unwrap();
        let mut reader = BufReader::new(socket);
        let mut request = String::new();
        reader.read_line(&mut request).await.unwrap();
        let mut socket = reader.into_inner();
        let tag = request.split_whitespace().next().unwrap();
        socket
            .write_all(format!("{tag} BAD STARTTLS unavailable\r\n").as_bytes())
            .await
            .unwrap();
        request
    });
    let config = ProtonMailConfig {
        imap_port: port,
        smtp_port: 1025,
        username: "bridge-user".into(),
        imap_security: ConnectionSecurity::StartTls,
        smtp_security: ConnectionSecurity::StartTls,
    };

    assert!(connect_imap(&config, "secret-password").await.is_err());
    let request = server.await.unwrap();
    assert!(request.contains("STARTTLS"), "request was {request:?}");
    assert!(!request.contains("bridge-user"));
    assert!(!request.contains("secret-password"));
}

const BRIDGE_LIKE_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDuTCCAqGgAwIBAgIUYcpYB6s3yzWpoXCbv6Ea2fzCQTQwDQYJKoZIhvcNAQEL
BQAwSzELMAkGA1UEBhMCQ0gxEjAQBgNVBAoMCVByb3RvbiBBRzEUMBIGA1UECwwL
UHJvdG9uIE1haWwxEjAQBgNVBAMMCTEyNy4wLjAuMTAeFw0yNjA5MjkxMTA4MDRa
Fw00NjA5MjQxMTA4MDRaMEsxCzAJBgNVBAYTAkNIMRIwEAYDVQQKDAlQcm90b24g
QUcxFDASBgNVBAsMC1Byb3RvbiBNYWlsMRIwEAYDVQQDDAkxMjcuMC4wLjEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCse355uXCZtTCK3VvveFQVFAfQ
28aolxflaOrMRYez39aL0bGwfDW7m6Xwyr9lqBlnR294aaxv6xJ5gC6tsp2jyYVA
ICgNoK+WGrHwStN2Q9SQtdMnq3nM6LroxxxPztqrkPsbMKgRR+xmDt/ZRjmhBxkY
4rP2j9Qtlw6h+uMBeeYmkIXUElEnG1bWFEI2FL/hcmtHcDL1wfQ1jp6a7Cd4bt/2
P7WILc7sskJIqhJGfciKeHA7s2A8jjNDawSsb8qkbDP0WMg+j82ttw3dNyohW87O
g3r0tTOPcrGfgc507ZW6fhr/mwe6VgwWGI3vsTIqAjr6k8Z+MTEGaCHK0UeZAgMB
AAGjgZQwgZEwHQYDVR0OBBYEFJgYRaNstqqkZzLEN5QMcBY+h4mjMB8GA1UdIwQY
MBaAFJgYRaNstqqkZzLEN5QMcBY+h4mjMA8GA1UdEQQIMAaHBH8AAAEwDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQAG3Zd6Kd5ipwi4x2+flrcpW+tp
ba6+uY/6UDxZ7yY6XCWl8eBFqQEGOIaX/ySP1WItZvx7vjkhdGMgBSa10WEWvSQ7
7M8Y6bJFmS17ewRcM0tzbQbg/KMeMXQ4EyIHjA0h7kFNHvH5wo4yOZl676gQipjr
Jw+rGA/HdJRkryejpPRITVPCd4zr6oswdFisXzEeA6i/Opk6/knFXqlwQuvnjaD8
Kgw3H8lHdB+e1qb0WAh6ZhSPXkkCAMU7GzEPfouqkoi07uWT+xyjMGJq7auzO+0a
6CYDSe/ZroJ9qBdnGoMAORK1EP9YAheicnprcfCBBCXcoDM9xb0LrtRKbsA9
-----END CERTIFICATE-----";

// Throwaway key for the self-signed 127.0.0.1 test certificate above; it guards nothing.
// nosemgrep: detected-private-key
const BRIDGE_LIKE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArHt+eblwmbUwit1b73hUFRQH0NvGqJcX5WjqzEWHs9/Wi9Gx
sHw1u5ul8Mq/ZagZZ0dveGmsb+sSeYAurbKdo8mFQCAoDaCvlhqx8ErTdkPUkLXT
J6t5zOi66MccT87aq5D7GzCoEUfsZg7f2UY5oQcZGOKz9o/ULZcOofrjAXnmJpCF
1BJRJxtW1hRCNhS/4XJrR3Ay9cH0NY6emuwneG7f9j+1iC3O7LJCSKoSRn3Iinhw
O7NgPI4zQ2sErG/KpGwz9FjIPo/NrbcN3TcqIVvOzoN69LUzj3Kxn4HOdO2Vun4a
/5sHulYMFhiN77EyKgI6+pPGfjExBmghytFHmQIDAQABAoIBABtvKRbDYB2SrD3q
J41XXkhb/0JBMr/uCGb84RvMk2EQ4Vcr609e8kz83NAH75mDu0aqHhjQ9hR3F2Er
+kC2gExk6UTh2H0Sads+M788p5XQBCdgRE2zAJSPD+umf+JRzIYtcUNJ4fGdtwQk
qYYtnUz3jA5hQK6fAeiedj1dYm4BaoMu/W4ZTAQvFlQR0euKQPad5aeBr+pJsAPZ
C24l/H47kaqnfBvANiXuR+m/MuFUxBZm3zk18hVUHEfxF1AFYqot/TfCilYFPzCb
peSbGe4ccyduTpf1XBNIA01++GJd7TOUZqmV9DBXASHRe4t8VD9aH22QHkU8/h2i
/xtAEeECgYEA44mmkwBcl5XUukk7ndZRVhFeApPKLizGyHo+9Tp1iRyNmD0QcWoG
EZc2tupTmAEqIxf5ZLp3XeSJtVNnRSl71111Hf9lFb3kTlLCT12b4iooVxLFcCFq
BE7zazpHBjoWFYZ4zqzRH/vGozsdDSuFj2I+4x5KQ+XN1eZDJocY49sCgYEAwg7U
UmH8NJ6PPl0ZuRF3RNrp3dyHxsysuQ3Na4I4qm+4z1TCphOi4SMT3IKCkdWLT4Mf
nnZNN7QCfNsOkn4fTdxEHd70Cer4YrkxGN5H0USmXxRQdfGmP1jCTlC9rto4XvZ8
gAtbWPPr6SFBHjaE1vNrWtC04omSn260e/7HlpsCgYEAsenz4YWq4Kw7Rd31S5lE
x/OUepdsw2YnmKJdkApB1RAKdztoHAY28JI4KhZXfseKVx5r1yMmKriEJNAuM5oY
R3HAHdCRDcsJNWToon4jYVhtaog28VJvPycslm9fEbNhiTs4QwJGEqgfzYpvUNjy
+gZr/dK1ZxnNNK9zWjDQeXkCgYAIaAoMk5AQW3oLEo9ls/r9sZoF8WK0WvN0hMOM
T7TStUpFOP/BoAIjTJi0qbasSJrjU+PPwoIv0o11CSxFbk8+2TbeMGVT9KjT5f/Z
eu+TgizO25tssI4qGlc4e0jsRSnB+12DUnqfjNmAXN9sRqJUiXDyGy5qzdjbLTmG
UZAl1wKBgBETtnXoqw/K8Iprt0rlLcHzfPxcpz6b3tVh4L+tO/f8fCihza40t1Ch
SaOAnn+qbb0jCFMkq37ctNrCwsdIJPc7vfJQoh7k3FUZ6i0DcBNDeT/SIA38O+WK
7nGnV0KbDfZ9hLqCAPiYg+YOO3iX6FI9khHDexAEqXdB2Dp5/EQO
-----END RSA PRIVATE KEY-----";

#[tokio::test]
async fn a_self_signed_bridge_certificate_is_accepted() {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from_pem_slice(BRIDGE_LIKE_CERT.as_bytes()).unwrap()],
        PrivateKeyDer::from_pem_slice(BRIDGE_LIKE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind((BRIDGE_HOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        tls.write_all(b"* OK test bridge\r\n").await.unwrap();
        let mut reader = BufReader::new(tls);
        let mut request = String::new();
        reader.read_line(&mut request).await.unwrap();
        let tag = request.split_whitespace().next().unwrap().to_string();
        let tls = reader.get_mut();
        tls.write_all(format!("{tag} OK LOGIN completed\r\n").as_bytes())
            .await
            .unwrap();
        tls.flush().await.unwrap();
        request
    });
    let config = ProtonMailConfig {
        imap_port: port,
        imap_security: ConnectionSecurity::Tls,
        ..bridge_config()
    };

    connect_imap(&config, "secret-password")
        .await
        .expect("the certificate is not trusted by the OS but should be accepted");
    assert!(server.await.unwrap().contains("LOGIN"));
}

#[test]
fn a_certificate_that_does_not_name_the_bridge_host_is_rejected() {
    use rustls::pki_types::pem::PemObject;

    let cert = CertificateDer::from_pem_slice(BRIDGE_LIKE_CERT.as_bytes()).unwrap();
    let verifier = AcceptBridgeCertificate(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let other_host = ServerName::try_from("localhost").unwrap();

    assert!(verifier
        .verify_server_cert(&cert, &[], &other_host, &[], UnixTime::now())
        .is_err());
}

#[tokio::test]
#[ignore = "requires a running Proton Mail Bridge"]
async fn live_bridge_starttls_smoke_test() {
    let config = ProtonMailConfig {
        imap_port: 1143,
        smtp_port: 1025,
        username: "lumo-bridge-smoke-test@invalid".into(),
        imap_security: ConnectionSecurity::StartTls,
        smtp_security: ConnectionSecurity::StartTls,
    };
    let error = connect_imap(&config, "intentionally-invalid-password")
        .await
        .expect_err("the deliberately invalid login should be rejected");
    assert!(
        error.starts_with("IMAP login connection failed:"),
        "TLS failed before login: {error}"
    );
}
