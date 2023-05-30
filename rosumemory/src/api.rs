use std::net::SocketAddr;

use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use rosumemory_lib::models::beatmap::Beatmap;
use serde::{Deserialize, Serialize};

use crate::{
    context::SharedContext,
    models::gosumemory::{
        beatmap::{GosumemoryBeatmap, GosumemoryBeatmapMetadata},
        Gosumemory, GosumemoryMenu,
    },
};

pub async fn serve(shared_context: SharedContext) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/json", get(json_route))
        .route("/ws", get(ws_route))
        .with_state(shared_context);

    // TODO: config for port
    let addr = SocketAddr::from(([127, 0, 0, 1], 24050));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn build_gosumemory_response(shared_context: SharedContext) -> anyhow::Result<Option<Gosumemory>> {
    let state = shared_context.shared.state.lock().unwrap();
    if !state.ready {
        return Ok(None);
    }

    let beatmap = unsafe { Beatmap::from_ptr(state.osu_pid, state.beatmap_ptr as *mut u8)? };

    Ok(Some(Gosumemory {
        menu: GosumemoryMenu {
            bm: GosumemoryBeatmap {
                metadata: GosumemoryBeatmapMetadata {
                    artist: beatmap.artist_romanised,
                    artist_original: beatmap.artist,
                    title: beatmap.title_romanised,
                    title_original: beatmap.title,
                },
            },
        },
    }))
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn new(error: String) -> Self {
        Self { error }
    }
}

async fn json_route(
    State(shared_context): State<SharedContext>,
) -> Result<Json<Gosumemory>, Json<ErrorResponse>> {
    let response = build_gosumemory_response(shared_context);

    match response {
        Ok(response) => match response {
            Some(response) => Ok(Json(response)),
            None => Err(Json(ErrorResponse::new(
                "osu! is not fully loaded".to_string(),
            ))),
        },
        Err(error) => Err(Json(ErrorResponse::new(error.to_string()))),
    }
}

async fn ws_route(
    ws: WebSocketUpgrade,
    State(shared_context): State<SharedContext>,
) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        loop {
            let ready: bool;
            {
                let state = shared_context.shared.state.lock().unwrap();
                ready = state.ready;
            }

            if ready {
                if let Ok(Some(response)) = build_gosumemory_response(shared_context.clone()) {
                    // TODO: does gosumemory send text or binary?
                    if socket
                        .send(Message::Text(serde_json::to_string(&response).unwrap()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
}
