use std::str::FromStr;
use std::{net::SocketAddr, path::Path};

use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use rosu_pp::{Beatmap, BeatmapExt, GameMode};
use rosumemory_lib::osu;
use serde::{Deserialize, Serialize};

use crate::{
    context::SharedContext,
    models::gosumemory::{
        beatmap::{
            GosumemoryBeatmap, GosumemoryBeatmapMetadata, GosumemoryBeatmapStats,
            GosumemoryBeatmapTime,
        },
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

    let beatmap = unsafe { osu::beatmap::from_ptr(state.osu_pid, state.beatmap_ptr as *mut u8)? };
    let play_time =
        unsafe { osu::play_time::from_ptr(state.osu_pid, state.play_time_addr as *mut u8)? };
    let game_mode =
        unsafe { osu::game_mode::from_ptr(state.osu_pid, state.base_address as *mut u8)? };
    let menu_mods =
        unsafe { osu::menu_mods::from_ptr(state.osu_pid, state.menu_mods_addr as *mut u8)? };

    let osu_file_path = Path::new(&state.osu_songs_folder)
        .join(&beatmap.folder)
        .join(&beatmap.osu_file_name);

    // TODO: allow/force akatsuki-pp-rs for rx/ap?
    let map = Beatmap::from_path(osu_file_path).expect("failed to read beatmap file");
    let calc_result = map
        .pp()
        .mode(match game_mode {
            0 => GameMode::Osu,
            1 => GameMode::Taiko,
            2 => GameMode::Catch,
            3 => GameMode::Mania,
            _ => unreachable!(),
        })
        .mods(menu_mods)
        .calculate();

    let max_combo = calc_result.difficulty_attributes().max_combo() as i32;

    // TODO: this is clunky af
    let rounded_sr = f32::from_str(&format!("{:.2}", calc_result.stars()))?;

    Ok(Some(Gosumemory {
        menu: GosumemoryMenu {
            bm: GosumemoryBeatmap {
                time: GosumemoryBeatmapTime { play_time },
                id: beatmap.map_id,
                set: beatmap.set_id,
                md5: beatmap.md5,
                ranked_status: beatmap.ranked_status,
                metadata: GosumemoryBeatmapMetadata {
                    artist: beatmap.artist_romanised,
                    artist_original: beatmap.artist,
                    title: beatmap.title_romanised,
                    title_original: beatmap.title,
                    mapper: beatmap.creator,
                    difficulty: beatmap.difficulty,
                },
                stats: GosumemoryBeatmapStats {
                    max_combo,
                    memory_ar: beatmap.ar,
                    memory_cs: beatmap.cs,
                    memory_od: beatmap.od,
                    memory_hp: beatmap.hp,
                    full_sr: rounded_sr,
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
