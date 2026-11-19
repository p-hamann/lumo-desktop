//! The tools the connector offers and their input schemas.

use super::{DEFAULT_MESSAGES, DEFAULT_RECENT_DAYS, MAX_MESSAGES, MAX_RECENT_DAYS};
use crate::tools::registry::ToolDefinition;
use serde_json::{json, Value};

pub(super) fn tool(
    name: &str,
    title: &str,
    description: &str,
    input_schema: Value,
) -> ToolDefinition {
    ToolDefinition {
        read_only: match name {
            "list_mailboxes" | "list_messages" | "search_messages" | "read_message" => Some(true),
            "mark_read" | "move_messages" | "send_email" => Some(false),
            _ => None,
        },
        name: name.into(),
        title: Some(title.into()),
        description: description.into(),
        input_schema,
        ..Default::default()
    }
}

pub(super) fn list_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "default": "INBOX" },
            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_MESSAGES, "default": DEFAULT_MESSAGES },
            "days": { "type": "integer", "minimum": 1, "maximum": MAX_RECENT_DAYS, "default": DEFAULT_RECENT_DAYS, "description": "Only include messages received within this many days" }
        }
    })
}

pub(super) fn search_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "default": "INBOX" },
            "text": { "type": "string" },
            "from": { "type": "string" },
            "to": { "type": "string" },
            "subject": { "type": "string" },
            "since": { "type": "string", "description": "Inclusive date in YYYY-MM-DD format" },
            "before": { "type": "string", "description": "Exclusive date in YYYY-MM-DD format" },
            "unread": { "type": "boolean" },
            "limit": { "type": "integer", "minimum": 1, "maximum": MAX_MESSAGES, "default": DEFAULT_MESSAGES }
        }
    })
}

pub(super) fn read_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "default": "INBOX" },
            "uid": { "type": "integer", "minimum": 1 },
            "format": { "type": "string", "enum": ["text", "html", "both"], "default": "text", "description": "Body format to return; HTML is returned as source and is not rendered" }
        },
        "required": ["uid"]
    })
}

pub(super) fn list_mailboxes_schema() -> Value {
    json!({ "type": "object", "properties": {} })
}

fn uids_schema() -> Value {
    json!({
        "type": "array",
        "items": { "type": "integer", "minimum": 1 },
        "minItems": 1,
        "maxItems": MAX_MESSAGES,
        "description": "UIDs of the messages in the mailbox, as list_messages or search_messages return them"
    })
}

pub(super) fn mark_read_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "default": "INBOX" },
            "uids": uids_schema(),
            "read": { "type": "boolean", "default": true, "description": "false marks the messages as unread again" }
        },
        "required": ["uids"]
    })
}

pub(super) fn move_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "mailbox": { "type": "string", "default": "INBOX" },
            "uids": uids_schema(),
            "destination": { "type": "string", "description": "Target mailbox, exactly as list_mailboxes returns it, e.g. Archive or Folders/Invoices" }
        },
        "required": ["uids", "destination"]
    })
}

pub(super) fn send_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "to": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
            "cc": { "type": "array", "items": { "type": "string" } },
            "bcc": { "type": "array", "items": { "type": "string" } },
            "subject": { "type": "string" },
            "body": { "type": "string", "description": "Required plain-text body and fallback for HTML-capable clients" },
            "html_body": { "type": "string", "description": "Optional HTML alternative" }
        },
        "required": ["to", "subject", "body"]
    })
}
