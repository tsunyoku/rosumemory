use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use rosumemory::{
    api,
    context::{Shared, SharedContext},
    ensure_osu,
};

async fn wrapped_main() -> anyhow::Result<()> {
    let context = ensure_osu().await?;
    let shared = Arc::new(Shared {
        state: Mutex::new(context),
    });
    let shared_context = SharedContext { shared };

    // TODO: background task to poll osu process and stuff

    api::serve(shared_context.clone()).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    wrapped_main().await.unwrap_or_else(|err| {
        eprintln!("error: {}", err);

        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        write!(stdout, "Press any key to continue...").unwrap();
        stdout.flush().unwrap();

        let _ = stdin.read(&mut [0u8]).unwrap();
    })
}
