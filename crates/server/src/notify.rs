//! Email and webhook notifications.

use std::time::Duration;

use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message, SmtpTransport, Transport};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{now, Shared};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSettings {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// "starttls" (default), "tls" (implicit, port 465) or "none".
    #[serde(default)]
    pub security: String,
    #[serde(default)]
    pub username: String,
    /// Never sent to the browser; an empty value on update keeps the stored one.
    #[serde(default)]
    pub password: String,
    pub from: String,
    pub to: Vec<String>,
}

fn default_port() -> u16 {
    587
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookSettings {
    pub url: String,
    /// "generic", "slack" or "teams".
    #[serde(default)]
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifySettings {
    #[serde(default)]
    pub email: Option<EmailSettings>,
    #[serde(default)]
    pub webhook: Option<WebhookSettings>,
    /// Also alert on backups that completed with warnings.
    #[serde(default = "yes")]
    pub on_warning: bool,
    /// Alert when a machine has not checked in for this long (0 = off).
    #[serde(default = "default_offline")]
    pub offline_hours: u32,
    /// Alert when a machine with an enabled plan has no good backup for this long (0 = off).
    #[serde(default = "default_overdue")]
    pub overdue_days: u32,
}

fn yes() -> bool {
    true
}
fn default_offline() -> u32 {
    24
}
fn default_overdue() -> u32 {
    2
}

impl Default for NotifySettings {
    fn default() -> Self {
        NotifySettings {
            email: None,
            webhook: None,
            on_warning: true,
            offline_hours: 24,
            overdue_days: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub severity: Severity,
    pub subject: String,
    pub body: String,
    /// Path in the web UI, e.g. "/machines/<id>".
    pub link: Option<String>,
}

pub const KEY: &str = "notifications";

/// Queue an event for delivery on all configured channels.
pub fn send(st: &Shared, ev: Event) {
    let cfg: NotifySettings = crate::db::get_setting(&st.db(), KEY);
    if cfg.email.is_none() && cfg.webhook.is_none() {
        return;
    }
    let base = st.cfg.public_url.clone();
    let st = st.clone();
    // Delivery may block on the network; keep it off the async runtime.
    std::thread::spawn(move || deliver(&st, &cfg, &ev, base.as_deref()));
}

/// Deliver synchronously; returns per-channel results (for "send test").
pub fn deliver(
    st: &Shared,
    cfg: &NotifySettings,
    ev: &Event,
    base: Option<&str>,
) -> Vec<(String, Result<(), String>)> {
    let link = match (base, &ev.link) {
        (Some(b), Some(l)) => Some(format!("{}{l}", b.trim_end_matches('/'))),
        _ => None,
    };
    let mut out = vec![];
    if let Some(e) = &cfg.email {
        out.push(("email".to_string(), send_email(e, ev, link.as_deref())));
    }
    if let Some(w) = &cfg.webhook {
        out.push(("webhook".to_string(), send_webhook(w, ev, link.as_deref())));
    }
    let db = st.db();
    for (ch, r) in &out {
        let _ = db.execute(
            "INSERT INTO notifications (at, channel, subject, ok, error) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now(), ch, ev.subject, r.is_ok(), r.as_ref().err()],
        );
        if let Err(e) = r {
            tracing::warn!(channel = %ch, error = %e, "notification failed");
        }
    }
    let _ = db.execute("DELETE FROM notifications WHERE id NOT IN (SELECT id FROM notifications ORDER BY id DESC LIMIT 500)", []);
    out
}

fn text(ev: &Event, link: Option<&str>) -> String {
    let mut t = ev.body.clone();
    if let Some(l) = link {
        t.push_str(&format!("\n\nOpen in Fenrir-Backup: {l}"));
    }
    t
}

pub fn send_email(e: &EmailSettings, ev: &Event, link: Option<&str>) -> Result<(), String> {
    let from: Mailbox = e.from.parse().map_err(|x| format!("sender address: {x}"))?;
    let mut b = Message::builder()
        .from(from)
        .subject(format!("[Fenrir-Backup] {}", ev.subject));
    if e.to.is_empty() {
        return Err("no recipients configured".into());
    }
    for t in &e.to {
        b = b.to(t
            .parse::<Mailbox>()
            .map_err(|x| format!("recipient {t}: {x}"))?);
    }
    let msg = b
        .header(ContentType::TEXT_PLAIN)
        .body(text(ev, link))
        .map_err(|x| x.to_string())?;
    let tls = || TlsParameters::new(e.host.clone()).map_err(|x| x.to_string());
    let mut tb = SmtpTransport::builder_dangerous(&e.host)
        .port(e.port)
        .timeout(Some(Duration::from_secs(20)));
    tb = match e.security.as_str() {
        "none" => tb.tls(Tls::None),
        "tls" => tb.tls(Tls::Wrapper(tls()?)),
        _ => tb.tls(Tls::Required(tls()?)),
    };
    if !e.username.is_empty() {
        tb = tb.credentials(Credentials::new(e.username.clone(), e.password.clone()));
    }
    tb.build()
        .send(&msg)
        .map(|_| ())
        .map_err(|x| format!("SMTP: {x}"))
}

pub fn webhook_payload(w: &WebhookSettings, ev: &Event, link: Option<&str>) -> serde_json::Value {
    match w.format.as_str() {
        "slack" => serde_json::json!({ "text": format!("*{}*\n{}", ev.subject, text(ev, link)) }),
        "teams" => serde_json::json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": ev.subject,
            "themeColor": match ev.severity { Severity::Error => "D32F2F", Severity::Warning => "F59E0B", Severity::Info => "0F9B8E" },
            "title": ev.subject,
            "text": text(ev, link).replace('\n', "<br>"),
        }),
        _ => serde_json::json!({
            "source": "fenrir-backup",
            "severity": ev.severity,
            "subject": ev.subject,
            "body": ev.body,
            "link": link,
            "at": now(),
        }),
    }
}

pub fn send_webhook(w: &WebhookSettings, ev: &Event, link: Option<&str>) -> Result<(), String> {
    if !(w.url.starts_with("https://") || w.url.starts_with("http://")) {
        return Err("webhook URL must start with https:// or http://".into());
    }
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .try_proxy_from_env(protocol::net::use_env_proxy(
            &w.url,
            &protocol::net::no_proxy_env(),
        ))
        .build()
        .post(&w.url)
        .send_json(webhook_payload(w, ev, link))
        .map(|_| ())
        .map_err(|e| format!("webhook: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_formats() {
        let ev = Event {
            severity: Severity::Error,
            subject: "Backup failed: web01".into(),
            body: "disk read error".into(),
            link: Some("/machines/x".into()),
        };
        let slack = webhook_payload(
            &WebhookSettings {
                url: String::new(),
                format: "slack".into(),
            },
            &ev,
            Some("https://b/machines/x"),
        );
        assert!(slack["text"]
            .as_str()
            .unwrap()
            .starts_with("*Backup failed: web01*"));
        assert!(slack["text"]
            .as_str()
            .unwrap()
            .contains("https://b/machines/x"));
        let teams = webhook_payload(
            &WebhookSettings {
                url: String::new(),
                format: "teams".into(),
            },
            &ev,
            None,
        );
        assert_eq!(teams["themeColor"], "D32F2F");
        let generic = webhook_payload(&WebhookSettings::default(), &ev, None);
        assert_eq!(generic["severity"], "error");
        assert_eq!(generic["source"], "fenrir-backup");
    }

    #[test]
    fn settings_defaults() {
        let s: NotifySettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, NotifySettings::default());
        assert!(s.on_warning);
    }
}
