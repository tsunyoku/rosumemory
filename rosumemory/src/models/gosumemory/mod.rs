use serde::{Deserialize, Serialize};

pub mod beatmap;

#[derive(Serialize, Deserialize)]
pub struct GosumemoryMenu {
    pub bm: beatmap::GosumemoryBeatmap,
}

#[derive(Serialize, Deserialize)]
pub struct Gosumemory {
    pub menu: GosumemoryMenu,
}
