use super::super::auth::{
    keychain_secrets, AuthMechanism, CredentialState, Interactive, ProtonBridgeInfo, Readiness,
    Secrets, Stored,
};
use super::super::connector_state::ToolPolicy;
use super::super::error::{AuthError, ToolError};
use super::super::icons::bundled_icon_data_uri;
use super::super::registry::{Connector, ConnectorDescriptor, Credentialed, ToolDefinition};
use crate::account::AccountId;
use async_imap::types::{Fetch, Name, NameAttribute};
use async_trait::async_trait;
use futures::TryStreamExt;
use lettre::AsyncTransport;
use log::warn;
use serde_json::{json, Value};
use std::sync::RwLock;
use std::time::Duration;
use tauri::AppHandle;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;

mod config;
mod message;
mod schema;
mod transport;

use config::{validate_config, SetupInput};
use message::{
    build_outgoing_message, build_search_query, destination_arg, full_message, limit_arg,
    message_summary, read_format_arg, recent_days_arg, recent_since_query, seen_flag_query,
    string_arg, uid_set_arg,
};
use schema::{
    list_mailboxes_schema, list_schema, mark_read_schema, move_schema, read_schema, search_schema,
    send_schema, tool,
};
use transport::{connect_imap, describe_connection_error, security_name, smtp_transport};

pub use config::{AccountConfigFile, ConfigFile, ProtonMailConfig};

const SECRET_NAME: &str = "proton_mail:password";
const BRIDGE_HOST: &str = "127.0.0.1";
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_MESSAGES: usize = 50;
const DEFAULT_MESSAGES: usize = 20;
const DEFAULT_RECENT_DAYS: u64 = 30;
const MAX_RECENT_DAYS: u64 = 365;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_BODY_CHARS: usize = 100_000;
const MAX_HTML_CHARS: usize = 250_000;

type ImapSession = async_imap::Session<TlsStream<TcpStream>>;

pub struct ProtonMailConnector {
    secrets: Secrets,
    storage: Box<dyn ConfigFile>,
    config: RwLock<Option<ProtonMailConfig>>,
    credentials: RwLock<CredentialState>,
}

impl ProtonMailConnector {
    pub fn new(
        storage: Box<dyn ConfigFile>,
        secrets: Secrets,
        credentials: CredentialState,
    ) -> Self {
        let config = storage
            .load()
            .map_err(|e| warn!("failed to load Proton Mail config: {e}"))
            .ok()
            .flatten();
        Self {
            secrets,
            storage,
            config: RwLock::new(config),
            credentials: RwLock::new(credentials),
        }
    }

    /// Probes the keychain once, which is what keeps [`Connector::readiness`] synchronous.
    pub async fn from_account(app_handle: AppHandle, account: AccountId) -> Self {
        let secrets = keychain_secrets(account.clone());
        let credentials = CredentialState::of(secrets.load(SECRET_NAME).await);
        Self::new(
            Box::new(AccountConfigFile {
                app_handle,
                account,
            }),
            secrets,
            credentials,
        )
    }

    fn credentials(&self) -> CredentialState {
        *self
            .credentials
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set_credentials(&self, state: CredentialState) {
        *self
            .credentials
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = state;
    }

    fn current_config(&self) -> Result<ProtonMailConfig, ToolError> {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(ToolError::NotAuthenticated)
    }

    async fn current_password(&self) -> Result<String, ToolError> {
        self.secrets
            .load(SECRET_NAME)
            .await
            .map_err(ToolError::ExecutionFailed)?
            .ok_or(ToolError::NotAuthenticated)
    }

    /// Proves the stored settings still reach Bridge, without changing them.
    async fn verify_stored(&self) -> Result<Stored, AuthError> {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(AuthError::RequiresSetup)?;
        let loaded = self.secrets.load(SECRET_NAME).await;
        self.set_credentials(CredentialState::of(loaded.clone()));
        let password = match loaded {
            Ok(Some(password)) if !password.is_empty() => password,
            Ok(_) => return Err(AuthError::RequiresSetup),
            Err(_) => return Err(AuthError::Failed(
                "secure storage is unavailable, so the stored Bridge password could not be read"
                    .into(),
            )),
        };
        Self::validate_credentials(&config, &password)
            .await
            .map_err(AuthError::Failed)?;
        Ok(Stored::Nothing)
    }

    async fn validate_credentials(config: &ProtonMailConfig, password: &str) -> Result<(), String> {
        let mut session = connect_imap(config, password).await?;
        timeout(IO_TIMEOUT, session.noop())
            .await
            .map_err(|_| "IMAP validation timed out".to_string())?
            .map_err(|e| describe_connection_error("IMAP", &e.to_string()))?;
        let _ = timeout(IO_TIMEOUT, session.logout()).await;

        let smtp = smtp_transport(config, password)?;
        let available = timeout(IO_TIMEOUT, smtp.test_connection())
            .await
            .map_err(|_| "SMTP validation timed out".to_string())?
            .map_err(|e| describe_connection_error("SMTP", &e.to_string()))?;
        if !available {
            return Err("SMTP connection did not respond successfully".into());
        }
        Ok(())
    }

    async fn with_session(&self) -> Result<ImapSession, ToolError> {
        let config = self.current_config()?;
        let password = self.current_password().await?;
        connect_imap(&config, &password)
            .await
            .map_err(ToolError::Unreachable)
    }

    async fn message_uids(
        &self,
        mailbox: &str,
        query: &str,
        limit: usize,
    ) -> Result<(ImapSession, Vec<u32>), ToolError> {
        let mut session = self.with_session().await?;
        timeout(IO_TIMEOUT, session.select(mailbox))
            .await
            .map_err(|_| ToolError::ExecutionFailed("selecting mailbox timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("could not select mailbox: {e}")))?;
        let found = timeout(IO_TIMEOUT, session.uid_search(query))
            .await
            .map_err(|_| ToolError::ExecutionFailed("mail search timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("mail search failed: {e}")))?;
        let mut uids: Vec<u32> = found.into_iter().collect();
        uids.sort_unstable_by(|a, b| b.cmp(a));
        uids.truncate(limit);
        Ok((session, uids))
    }

    async fn fetch_summaries(
        mut session: ImapSession,
        mailbox: &str,
        uids: &[u32],
    ) -> Result<Value, ToolError> {
        if uids.is_empty() {
            let _ = timeout(IO_TIMEOUT, session.logout()).await;
            return Ok(json!({ "mailbox": mailbox, "messages": [] }));
        }
        let uid_set = uids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let stream = timeout(
            IO_TIMEOUT,
            session.uid_fetch(
                uid_set,
                "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER])",
            ),
        )
        .await
        .map_err(|_| ToolError::ExecutionFailed("fetching message headers timed out".into()))?
        .map_err(|e| ToolError::ExecutionFailed(format!("fetching message headers failed: {e}")))?;
        let fetches: Vec<Fetch> = timeout(IO_TIMEOUT, stream.try_collect())
            .await
            .map_err(|_| ToolError::ExecutionFailed("reading message headers timed out".into()))?
            .map_err(|e| {
                ToolError::ExecutionFailed(format!("reading message headers failed: {e}"))
            })?;
        let mut messages = fetches
            .iter()
            .filter_map(message_summary)
            .collect::<Vec<_>>();
        messages.sort_by(|(a_time, a), (b_time, b)| {
            b_time.cmp(a_time).then_with(|| {
                b.get("uid")
                    .and_then(Value::as_u64)
                    .cmp(&a.get("uid").and_then(Value::as_u64))
            })
        });
        let messages = messages
            .into_iter()
            .map(|(_, message)| message)
            .collect::<Vec<_>>();
        let _ = timeout(IO_TIMEOUT, session.logout()).await;
        Ok(json!({ "mailbox": mailbox, "messages": messages }))
    }

    async fn list_messages(&self, input: Value) -> Result<Value, ToolError> {
        let mailbox = string_arg(&input, "mailbox").unwrap_or("INBOX");
        let limit = limit_arg(&input)?;
        let days = recent_days_arg(&input)?;
        let query = recent_since_query(days);
        let (session, uids) = self.message_uids(mailbox, &query, limit).await?;
        Self::fetch_summaries(session, mailbox, &uids).await
    }

    async fn search_messages(&self, input: Value) -> Result<Value, ToolError> {
        let mailbox = string_arg(&input, "mailbox").unwrap_or("INBOX");
        let limit = limit_arg(&input)?;
        let query = build_search_query(&input)?;
        let (session, uids) = self.message_uids(mailbox, &query, limit).await?;
        Self::fetch_summaries(session, mailbox, &uids).await
    }

    async fn read_message(&self, input: Value) -> Result<Value, ToolError> {
        let mailbox = string_arg(&input, "mailbox").unwrap_or("INBOX");
        let format = read_format_arg(&input)?;
        let uid = input
            .get("uid")
            .and_then(Value::as_u64)
            .filter(|uid| *uid > 0 && *uid <= u32::MAX as u64)
            .ok_or_else(|| ToolError::InvalidInput("uid must be a positive integer".into()))?;
        let mut session = self.with_session().await?;
        timeout(IO_TIMEOUT, session.select(mailbox))
            .await
            .map_err(|_| ToolError::ExecutionFailed("selecting mailbox timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("could not select mailbox: {e}")))?;
        let query =
            format!("(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[]<0.{MAX_MESSAGE_BYTES}>)");
        let stream = timeout(IO_TIMEOUT, session.uid_fetch(uid.to_string(), query))
            .await
            .map_err(|_| ToolError::ExecutionFailed("reading message timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("reading message failed: {e}")))?;
        let fetches: Vec<Fetch> = timeout(IO_TIMEOUT, stream.try_collect())
            .await
            .map_err(|_| ToolError::ExecutionFailed("reading message timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("reading message failed: {e}")))?;
        let fetch = fetches.first();
        let result = fetch
            .and_then(|fetch| full_message(fetch, format))
            .ok_or_else(|| {
                let oversized = fetch
                    .and_then(Fetch::body)
                    .is_some_and(|body| body.len() >= MAX_MESSAGE_BYTES);
                if oversized {
                    ToolError::ExecutionFailed(format!(
                        "message is larger than {MAX_MESSAGE_BYTES} bytes and the retrieved part could not be parsed"
                    ))
                } else {
                    ToolError::ExecutionFailed("message not found or could not be parsed".into())
                }
            });
        let _ = timeout(IO_TIMEOUT, session.logout()).await;
        result
    }

    async fn selected_session(&self, mailbox: &str) -> Result<ImapSession, ToolError> {
        let mut session = self.with_session().await?;
        timeout(IO_TIMEOUT, session.select(mailbox))
            .await
            .map_err(|_| ToolError::ExecutionFailed("selecting mailbox timed out".into()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("could not select mailbox: {e}")))?;
        Ok(session)
    }

    async fn list_mailboxes(&self) -> Result<Value, ToolError> {
        let mut session = self.with_session().await?;
        let listed = async {
            let stream = timeout(IO_TIMEOUT, session.list(Some(""), Some("*")))
                .await
                .map_err(|_| ToolError::ExecutionFailed("listing mailboxes timed out".into()))?
                .map_err(|e| {
                    ToolError::ExecutionFailed(format!("listing mailboxes failed: {e}"))
                })?;
            let names: Vec<Name> = timeout(IO_TIMEOUT, stream.try_collect())
                .await
                .map_err(|_| ToolError::ExecutionFailed("listing mailboxes timed out".into()))?
                .map_err(|e| {
                    ToolError::ExecutionFailed(format!("listing mailboxes failed: {e}"))
                })?;
            let mut mailboxes = names
                .iter()
                .filter(|name| !name.attributes().contains(&NameAttribute::NoSelect))
                .map(|name| name.name().to_string())
                .collect::<Vec<_>>();
            mailboxes.sort();
            Ok(json!({ "mailboxes": mailboxes }))
        }
        .await;
        let _ = timeout(IO_TIMEOUT, session.logout()).await;
        listed
    }

    async fn mark_read(&self, input: Value) -> Result<Value, ToolError> {
        let mailbox = string_arg(&input, "mailbox").unwrap_or("INBOX");
        let uid_set = uid_set_arg(&input)?;
        let query = seen_flag_query(&input)?;
        let mut session = self.selected_session(mailbox).await?;
        let stored = async {
            let stream = timeout(IO_TIMEOUT, session.uid_store(&uid_set, query))
                .await
                .map_err(|_| ToolError::ExecutionFailed("updating messages timed out".into()))?
                .map_err(|e| {
                    ToolError::ExecutionFailed(format!("updating messages failed: {e}"))
                })?;
            let _: Vec<Fetch> = timeout(IO_TIMEOUT, stream.try_collect())
                .await
                .map_err(|_| ToolError::ExecutionFailed("updating messages timed out".into()))?
                .map_err(|e| {
                    ToolError::ExecutionFailed(format!("updating messages failed: {e}"))
                })?;
            Ok(())
        }
        .await;
        let _ = timeout(IO_TIMEOUT, session.logout()).await;
        stored?;
        Ok(json!({
            "mailbox": mailbox,
            "uids": uid_set,
            "read": query.starts_with('+'),
        }))
    }

    async fn move_messages(&self, input: Value) -> Result<Value, ToolError> {
        let mailbox = string_arg(&input, "mailbox").unwrap_or("INBOX");
        let uid_set = uid_set_arg(&input)?;
        let destination = destination_arg(&input, mailbox)?;
        let mut session = self.selected_session(mailbox).await?;
        let moved = timeout(IO_TIMEOUT, session.uid_mv(&uid_set, destination))
            .await
            .map_err(|_| ToolError::ExecutionFailed("moving messages timed out".into()))
            .and_then(|result| {
                result
                    .map_err(|e| ToolError::ExecutionFailed(format!("moving messages failed: {e}")))
            });
        let _ = timeout(IO_TIMEOUT, session.logout()).await;
        moved?;
        Ok(json!({
            "mailbox": mailbox,
            "uids": uid_set,
            "destination": destination,
        }))
    }

    async fn send_email(&self, input: Value) -> Result<Value, ToolError> {
        let config = self.current_config()?;
        let password = self.current_password().await?;
        let message = build_outgoing_message(&config.username, &input)?;
        let smtp = smtp_transport(&config, &password).map_err(ToolError::Unreachable)?;
        let response = timeout(IO_TIMEOUT, smtp.send(message))
            .await
            .map_err(|_| ToolError::ExecutionFailed("sending email timed out".into()))?
            .map_err(|e| {
                ToolError::Unreachable(describe_connection_error("SMTP", &e.to_string()))
            })?;
        Ok(json!({ "sent": response.is_positive() }))
    }
}

#[async_trait]
impl Connector for ProtonMailConnector {
    fn id(&self) -> &str {
        "proton_mail"
    }

    fn descriptor(&self) -> ConnectorDescriptor {
        ConnectorDescriptor {
            id: "proton_mail".into(),
            display_name: "Proton Mail".into(),
            description: None,
            version: "1.0.0".into(),
            icon: bundled_icon_data_uri("proton_mail"),
            auth: AuthMechanism::ProtonBridge {
                config: self
                    .config
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .map(|config| ProtonBridgeInfo {
                        imap_port: config.imap_port,
                        smtp_port: config.smtp_port,
                        username: config.username.clone(),
                        imap_security: security_name(config.imap_security).into(),
                        smtp_security: security_name(config.smtp_security).into(),
                    }),
            },
        }
    }

    fn readiness(&self) -> Readiness {
        let has_config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some();
        if !has_config {
            return Readiness::blocked("Not connected");
        }
        match self.credentials().blocked_reason() {
            Some(reason) => Readiness::blocked(reason),
            None => Readiness::Ready,
        }
    }

    fn tools(&self) -> Vec<ToolDefinition> {
        vec![
            tool(
                "list_mailboxes",
                "List mailboxes",
                "List the mailboxes (folders and labels) a message can be read from or moved to.",
                list_mailboxes_schema(),
            ),
            tool(
                "list_messages",
                "List messages",
                "List recently received messages in a mailbox, newest first. Defaults to the last 30 days.",
                list_schema(),
            ),
            tool(
                "search_messages",
                "Search messages",
                "Search messages using structured IMAP filters.",
                search_schema(),
            ),
            tool(
                "read_message",
                "Read message",
                "Read one message by mailbox and UID as plain text, HTML, or both.",
                read_schema(),
            ),
            tool(
                "mark_read",
                "Mark as read",
                "Mark messages as read, or as unread again with read set to false.",
                mark_read_schema(),
            ),
            ToolDefinition {
                policy: ToolPolicy::Ask,
                ..tool(
                    "move_messages",
                    "Move messages",
                    "Move messages to another mailbox. Moving to a Labels/ mailbox applies that label; moving to Trash deletes the messages.",
                    move_schema(),
                )
            },
            ToolDefinition {
                policy: ToolPolicy::Ask,
                ..tool(
                    "send_email",
                    "Send email",
                    "Send a plain-text email, optionally with an HTML alternative, through Proton Mail Bridge.",
                    send_schema(),
                )
            },
        ]
    }

    async fn invoke(&self, tool_name: &str, input: Value) -> Result<Value, ToolError> {
        match tool_name {
            "list_mailboxes" => self.list_mailboxes().await,
            "list_messages" => self.list_messages(input).await,
            "search_messages" => self.search_messages(input).await,
            "read_message" => self.read_message(input).await,
            "mark_read" => self.mark_read(input).await,
            "move_messages" => self.move_messages(input).await,
            "send_email" => self.send_email(input).await,
            _ => Err(ToolError::UnknownTool(tool_name.into())),
        }
    }

    fn as_credentialed(&self) -> Option<&dyn Credentialed> {
        Some(self)
    }
}

#[async_trait]
impl Credentialed for ProtonMailConnector {
    async fn authenticate(
        &self,
        input: Option<Value>,
        _mode: Interactive,
    ) -> Result<Stored, AuthError> {
        let Some(input) = input else {
            return self.verify_stored().await;
        };
        let setup: SetupInput = serde_json::from_value(input)
            .map_err(|e| AuthError::Failed(format!("invalid Bridge settings: {e}")))?;
        let config = ProtonMailConfig {
            imap_port: setup.imap_port,
            smtp_port: setup.smtp_port,
            username: setup.username.trim().to_string(),
            imap_security: setup.imap_security,
            smtp_security: setup.smtp_security,
        };
        validate_config(&config).map_err(AuthError::Failed)?;
        let password = if setup.password.is_empty() {
            self.secrets
                .load(SECRET_NAME)
                .await
                .map_err(AuthError::Failed)?
                .ok_or_else(|| AuthError::Failed("Bridge password is required".into()))?
        } else {
            setup.password.clone()
        };
        Self::validate_credentials(&config, &password)
            .await
            .map_err(AuthError::Failed)?;
        self.storage.save(&config).map_err(AuthError::Failed)?;
        let wrote = if setup.password.is_empty() {
            Stored::Nothing
        } else {
            self.secrets
                .store(SECRET_NAME, &setup.password)
                .await
                .map_err(AuthError::Failed)?;
            Stored::Something
        };
        *self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(config);
        self.set_credentials(CredentialState::Present);
        Ok(wrote)
    }

    async fn forget(&self) -> Result<(), String> {
        self.secrets.delete(SECRET_NAME).await?;
        self.storage.delete()?;
        *self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.set_credentials(CredentialState::Absent);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
