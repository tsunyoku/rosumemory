use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmapMetadata {
    pub artist: String,
    #[serde(rename = "artistOriginal")]
    pub artist_original: String,
    pub title: String,
    #[serde(rename = "titleOriginal")]
    pub title_original: String,
    // TODO: add remaining fields
}

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmap {
    pub metadata: GosumemoryBeatmapMetadata,
}
