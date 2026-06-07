use tracing::info;

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(true)
        .with_thread_ids(true)
        .init();
    info!("NHP-AC tracing initialized");
}
