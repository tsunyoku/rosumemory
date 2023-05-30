use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmapMetadata {
    pub artist: String,
    #[serde(rename = "artistOriginal")]
    pub artist_original: String,
    pub title: String,
    #[serde(rename = "titleOriginal")]
    pub title_original: String,
    pub mapper: String,
    pub difficulty: String,
}

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmap {
    // TODO: time
    pub id: i32,
    pub set: i32,
    pub md5: String,
    #[serde(rename = "rankedStatus")]
    pub ranked_status: i32,
    pub metadata: GosumemoryBeatmapMetadata,
    // TODO: stats
    // TODO: path
    // TODO: wtf does `json:"-"` mean? (do i need HitObjectStats and BeatmapString?)
}
