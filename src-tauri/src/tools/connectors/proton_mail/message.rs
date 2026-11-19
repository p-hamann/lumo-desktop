//! Tool arguments, IMAP queries, and the messages read back.

use super::{
    DEFAULT_MESSAGES, DEFAULT_RECENT_DAYS, MAX_BODY_CHARS, MAX_HTML_CHARS, MAX_MESSAGES,
    MAX_MESSAGE_BYTES, MAX_RECENT_DAYS,
};
use crate::tools::error::ToolError;
use async_imap::types::Fetch;
use chrono::{Duration as ChronoDuration, NaiveDate, Utc};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::Message;
use mail_parser::{Address, MessageParser};
use serde_json::{json, Value};
use std::str::FromStr;

pub(super) fn string_arg<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

pub(super) fn required_string<'a>(input: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    string_arg(input, key).ok_or_else(|| ToolError::InvalidInput(format!("{key} is required")))
}

#[derive(Clone, Copy)]
pub(super) enum ReadFormat {
    Text,
    Html,
    Both,
}

pub(super) fn read_format_arg(input: &Value) -> Result<ReadFormat, ToolError> {
    match input
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("text")
    {
        "text" => Ok(ReadFormat::Text),
        "html" => Ok(ReadFormat::Html),
        "both" => Ok(ReadFormat::Both),
        other => Err(ToolError::InvalidInput(format!(
            "unsupported message format: {other}"
        ))),
    }
}

pub(super) fn validate_outgoing_body(body: &str, html_body: Option<&str>) -> Result<(), ToolError> {
    if body.chars().count() > MAX_BODY_CHARS {
        return Err(ToolError::InvalidInput(format!(
            "plain-text body exceeds the {MAX_BODY_CHARS} character limit"
        )));
    }
    if html_body.is_some_and(|html| html.chars().count() > MAX_HTML_CHARS) {
        return Err(ToolError::InvalidInput(format!(
            "HTML body exceeds the {MAX_HTML_CHARS} character limit"
        )));
    }
    Ok(())
}

pub(super) fn build_outgoing_message(username: &str, input: &Value) -> Result<Message, ToolError> {
    let subject = required_string(input, "subject")?;
    let body = required_string(input, "body")?;
    let html_body = string_arg(input, "html_body");
    validate_outgoing_body(body, html_body)?;
    let from = Mailbox::from_str(username).map_err(|e| {
        ToolError::InvalidInput(format!("Bridge username is not a valid email address: {e}"))
    })?;
    let to = mailbox_list(input, "to", true)?;
    let cc = mailbox_list(input, "cc", false)?;
    let bcc = mailbox_list(input, "bcc", false)?;

    let mut builder = Message::builder().from(from).subject(subject);
    for address in to {
        builder = builder.to(address);
    }
    for address in cc {
        builder = builder.cc(address);
    }
    for address in bcc {
        builder = builder.bcc(address);
    }
    match html_body {
        Some(html) => builder.multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(body.to_string()))
                .singlepart(SinglePart::html(html.to_string())),
        ),
        None => builder.singlepart(SinglePart::plain(body.to_string())),
    }
    .map_err(|e| ToolError::InvalidInput(format!("could not build email: {e}")))
}

pub(super) fn limit_arg(input: &Value) -> Result<usize, ToolError> {
    let limit = input
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MESSAGES as u64) as usize;
    if !(1..=MAX_MESSAGES).contains(&limit) {
        return Err(ToolError::InvalidInput(format!(
            "limit must be between 1 and {MAX_MESSAGES}"
        )));
    }
    Ok(limit)
}

pub(super) fn recent_days_arg(input: &Value) -> Result<u64, ToolError> {
    let days = input
        .get("days")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_RECENT_DAYS);
    if !(1..=MAX_RECENT_DAYS).contains(&days) {
        return Err(ToolError::InvalidInput(format!(
            "days must be between 1 and {MAX_RECENT_DAYS}"
        )));
    }
    Ok(days)
}

pub(super) fn recent_since_query(days: u64) -> String {
    let since = Utc::now().date_naive() - ChronoDuration::days(days as i64);
    format!("SINCE {}", since.format("%d-%b-%Y"))
}

/// The messages a mail-changing tool acts on: 1 to [`MAX_MESSAGES`] distinct UIDs, as an IMAP set.
pub(super) fn uid_set_arg(input: &Value) -> Result<String, ToolError> {
    let invalid = || {
        ToolError::InvalidInput(format!(
            "uids must list 1 to {MAX_MESSAGES} positive integers"
        ))
    };
    let values = input
        .get("uids")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or_else(invalid)?;
    let mut uids = values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|uid| *uid > 0 && *uid <= u32::MAX as u64)
                .ok_or_else(invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    uids.sort_unstable();
    uids.dedup();
    if uids.len() > MAX_MESSAGES {
        return Err(invalid());
    }
    Ok(uids
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

/// The `\Seen` change for `mark_read`: adds the flag unless `read` is false.
pub(super) fn seen_flag_query(input: &Value) -> Result<&'static str, ToolError> {
    match input.get("read") {
        None => Ok("+FLAGS.SILENT (\\Seen)"),
        Some(Value::Bool(true)) => Ok("+FLAGS.SILENT (\\Seen)"),
        Some(Value::Bool(false)) => Ok("-FLAGS.SILENT (\\Seen)"),
        Some(_) => Err(ToolError::InvalidInput("read must be a boolean".into())),
    }
}

/// The folder messages are moved to. It must differ from the one they are in.
pub(super) fn destination_arg<'a>(input: &'a Value, mailbox: &str) -> Result<&'a str, ToolError> {
    let destination = required_string(input, "destination")?;
    if destination.contains(['\r', '\n', '\0']) {
        return Err(ToolError::InvalidInput(
            "destination cannot contain line breaks".into(),
        ));
    }
    if destination == mailbox {
        return Err(ToolError::InvalidInput(
            "destination must differ from the mailbox the messages are in".into(),
        ));
    }
    Ok(destination)
}

pub(super) fn mailbox_list(
    input: &Value,
    key: &str,
    required: bool,
) -> Result<Vec<Mailbox>, ToolError> {
    let values = input.get(key).and_then(Value::as_array);
    if required && values.is_none_or(Vec::is_empty) {
        return Err(ToolError::InvalidInput(format!(
            "{key} requires at least one address"
        )));
    }
    values
        .into_iter()
        .flatten()
        .map(|value| {
            let address = value
                .as_str()
                .ok_or_else(|| ToolError::InvalidInput(format!("{key} entries must be strings")))?;
            Mailbox::from_str(address)
                .map_err(|e| ToolError::InvalidInput(format!("invalid {key} address: {e}")))
        })
        .collect()
}

pub(super) fn quote_imap(value: &str) -> Result<String, ToolError> {
    if value.contains(['\r', '\n', '\0']) {
        return Err(ToolError::InvalidInput(
            "search values cannot contain line breaks".into(),
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

pub(super) fn imap_date(value: &str) -> Result<String, ToolError> {
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map(|date| date.format("%d-%b-%Y").to_string())
        .map_err(|_| ToolError::InvalidInput("dates must use YYYY-MM-DD".into()))
}

pub(super) fn build_search_query(input: &Value) -> Result<String, ToolError> {
    let mut terms = Vec::new();
    for (key, command) in [
        ("text", "TEXT"),
        ("from", "FROM"),
        ("to", "TO"),
        ("subject", "SUBJECT"),
    ] {
        if let Some(value) = string_arg(input, key) {
            terms.push(format!("{command} {}", quote_imap(value)?));
        }
    }
    if let Some(value) = string_arg(input, "since") {
        terms.push(format!("SINCE {}", imap_date(value)?));
    }
    if let Some(value) = string_arg(input, "before") {
        terms.push(format!("BEFORE {}", imap_date(value)?));
    }
    if input.get("unread").and_then(Value::as_bool) == Some(true) {
        terms.push("UNSEEN".into());
    }
    if terms.is_empty() {
        terms.push("ALL".into());
    }
    let query = terms.join(" ");
    if query.is_ascii() {
        Ok(query)
    } else {
        Ok(format!("CHARSET UTF-8 {query}"))
    }
}

pub(super) fn addresses(addresses: Option<&Address<'_>>) -> Vec<Value> {
    addresses
        .into_iter()
        .flat_map(Address::iter)
        .map(|address| {
            json!({
                "name": address.name.as_deref(),
                "address": address.address.as_deref()
            })
        })
        .collect()
}

pub(super) fn message_summary(fetch: &Fetch) -> Option<(i64, Value)> {
    let header = fetch.header()?;
    parse_message_summary(
        header,
        fetch.uid,
        fetch.size,
        fetch.internal_date(),
        fetch.flags().map(|flag| format!("{flag:?}")).collect(),
    )
}

pub(super) fn parse_message_summary(
    header: &[u8],
    uid: Option<u32>,
    size: Option<u32>,
    received_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    flags: Vec<String>,
) -> Option<(i64, Value)> {
    let message = MessageParser::default().parse(header)?;
    let received_timestamp = received_at
        .as_ref()
        .map_or(i64::MIN, |date| date.timestamp());
    let value = json!({
        "uid": uid,
        "size": size,
        "from": addresses(message.from()),
        "to": addresses(message.to()),
        "subject": message.subject(),
        "date": message.date().map(|date| date.to_rfc3339()),
        "received_at": received_at.map(|date| date.to_rfc3339()),
        "message_id": message.message_id(),
        "flags": flags
    });
    Some((received_timestamp, value))
}

pub(super) fn full_message(fetch: &Fetch, format: ReadFormat) -> Option<Value> {
    parse_full_message(
        fetch.body()?,
        fetch.uid,
        fetch.size,
        fetch.internal_date(),
        format,
    )
}

pub(super) fn parse_full_message(
    body: &[u8],
    uid: Option<u32>,
    size: Option<u32>,
    received_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    format: ReadFormat,
) -> Option<Value> {
    let raw_truncated = body.len() >= MAX_MESSAGE_BYTES;
    let message = MessageParser::default().parse(body)?;
    let text = message.body_text(0).unwrap_or_default();
    let text_truncated = raw_truncated || text.chars().count() > MAX_BODY_CHARS;
    let body_text = truncate_chars(text.as_ref(), MAX_BODY_CHARS);
    let html = (!message.html_body.is_empty())
        .then(|| message.body_html(0))
        .flatten();
    let html_truncated = raw_truncated
        || html
            .as_ref()
            .is_some_and(|h| h.chars().count() > MAX_HTML_CHARS);
    let body_html = html
        .as_ref()
        .map(|html| truncate_chars(html.as_ref(), MAX_HTML_CHARS));
    let mut result = json!({
        "uid": uid,
        "size": size,
        "from": addresses(message.from()),
        "to": addresses(message.to()),
        "cc": addresses(message.cc()),
        "subject": message.subject(),
        "date": message.date().map(|date| date.to_rfc3339()),
        "received_at": received_at.map(|date| date.to_rfc3339()),
        "message_id": message.message_id(),
        "has_html": html.is_some(),
        "has_attachments": message.attachment_count() > 0,
        "raw_truncated": raw_truncated
    });
    let fields = result.as_object_mut()?;
    match format {
        ReadFormat::Text => {
            fields.insert("format".into(), json!("text"));
            fields.insert("body".into(), json!(body_text));
            fields.insert("truncated".into(), json!(text_truncated));
        }
        ReadFormat::Html => {
            if let Some(html) = body_html {
                fields.insert("format".into(), json!("html"));
                fields.insert("body".into(), json!(html));
                fields.insert("truncated".into(), json!(html_truncated));
            } else {
                fields.insert("format".into(), json!("text"));
                fields.insert("body".into(), json!(body_text));
                fields.insert("html_unavailable".into(), json!(true));
                fields.insert("truncated".into(), json!(text_truncated));
            }
        }
        ReadFormat::Both => {
            fields.insert("format".into(), json!("both"));
            fields.insert("body_text".into(), json!(body_text));
            fields.insert("body_html".into(), json!(body_html));
            fields.insert("text_truncated".into(), json!(text_truncated));
            fields.insert("html_truncated".into(), json!(html_truncated));
        }
    }
    Some(result)
}

pub(super) fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}
