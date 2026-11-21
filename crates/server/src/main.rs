use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use server::{router, schedule, tls, AppState, Config};

#[derive(Parser)]
#[command(
    name = "fenrir-server",
    version,
    about = "Fenrir-Backup management server and web UI"
)]
struct Args {
    /// Address and port to listen on.
    #[arg(long, default_value = "0.0.0.0:8443", env = "FENRIR_LISTEN")]
    listen: SocketAddr,
    /// Where the database and generated certificate live.
    #[arg(long, default_value = default_data_dir(), env = "FENRIR_DATA_DIR")]
    data_dir: PathBuf,
    /// URL agents use to reach this server, e.g. https://backup.example.com:8443.
    /// Default: the address the administrator's browser used.
    #[arg(long, env = "FENRIR_PUBLIC_URL")]
    public_url: Option<String>,
    /// Built web UI (ui/dist). Default: `ui` next to the executable, then ./ui/dist.
    #[arg(long, env = "FENRIR_UI_DIR")]
    ui_dir: Option<PathBuf>,
    /// Agent builds, laid out as <target-triple>/<file>. Default: `agents` next to the executable.
    #[arg(long, env = "FENRIR_AGENTS_DIR")]
    agents_dir: Option<PathBuf>,
    /// Certificate and key (PEM). Without them a self-signed certificate is
    /// generated and pinned by installers.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Extra DNS names / IPs for the self-signed certificate.
    #[arg(long = "tls-name")]
    tls_names: Vec<String>,
    /// Plain HTTP. Only behind a reverse proxy that terminates TLS.
    #[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
    http: bool,
    /// Seconds between agent check-ins.
    #[arg(long, default_value_t = 15)]
    poll_seconds: u32,
}

const fn default_data_dir() -> &'static str {
    if cfg!(windows) {
        r"C:\ProgramData\Fenrir-Backup\server"
    } else {
        "/var/lib/fenrir-server"
    }
}

fn beside_exe(name: &str) -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.join(name))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let a = Args::parse();
    std::fs::create_dir_all(&a.data_dir)
        .with_context(|| format!("creating {}", a.data_dir.display()))?;

    let tls = if a.http {
        tracing::warn!("serving plain HTTP: only do this behind a TLS-terminating reverse proxy");
        None
    } else if let (Some(c), Some(k)) = (&a.tls_cert, &a.tls_key) {
        Some(tls::load(c, k)?)
    } else {
        let mut names = a.tls_names.clone();
        if let Some(host) = a
            .public_url
            .as_deref()
            .and_then(|u| u.split("://").nth(1))
            .map(|h| h.split(['/', ':']).next().unwrap_or("").to_string())
        {
            if !host.is_empty() {
                names.push(host);
            }
        }
        if let Ok(h) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
            names.push(h);
        }
        Some(tls::self_signed(&a.data_dir, names)?)
    };

    let ui_dir = a
        .ui_dir
        .clone()
        .or_else(|| beside_exe("ui").filter(|p| p.join("index.html").is_file()))
        .or_else(|| Some(PathBuf::from("ui/dist")).filter(|p| p.join("index.html").is_file()));
    let agents_dir = a
        .agents_dir
        .clone()
        .or_else(|| beside_exe("agents"))
        .unwrap_or_else(|| PathBuf::from("agents"));

    let conn = rusqlite::Connection::open(a.data_dir.join("fenrir.db"))?;
    let state = AppState::new(
        conn,
        Config {
            public_url: a.public_url.clone(),
            agents_dir: agents_dir.clone(),
            ui_dir: ui_dir.clone(),
            tls: tls.as_ref().map(|t| t.info.clone()),
            poll_seconds: a.poll_seconds.clamp(5, 300),
        },
    )?;
    tokio::spawn(schedule::scheduler_loop(state.clone()));

    tracing::info!(
        listen = %a.listen,
        data_dir = %a.data_dir.display(),
        ui_dir = ?ui_dir,
        agents_dir = %agents_dir.display(),
        cert_sha256 = ?tls.as_ref().map(|t| &t.info.cert_sha256),
        "fenrir-server starting"
    );
    let app = router(state).into_make_service();
    match tls {
        Some(t) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let cfg =
                axum_server::tls_rustls::RustlsConfig::from_pem(t.cert_pem, t.key_pem).await?;
            let handle = axum_server::Handle::new();
            let h2 = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                h2.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
            });
            axum_server::bind_rustls(a.listen, cfg)
                .handle(handle)
                .serve(app)
                .await?;
        }
        None => {
            let l = tokio::net::TcpListener::bind(a.listen).await?;
            axum::serve(l, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }
    Ok(())
}

/// Ctrl-C, or SIGTERM from systemd / `docker stop`. As PID 1 in a
/// container the process gets no default SIGTERM action, so it must be
/// handled explicitly.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
}
