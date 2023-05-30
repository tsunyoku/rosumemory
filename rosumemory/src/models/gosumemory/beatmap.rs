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
pub struct GosumemoryBeatmapStats {
    // TODO: do i actually need to differentiate these? can i just reuse memory?
    // ^ ar, cs, od, hp, sr, bpm
    #[serde(rename = "maxCombo")]
    pub max_combo: i32,
    #[serde(rename = "memoryAR")]
    pub memory_ar: f32,
    #[serde(rename = "memoryCS")]
    pub memory_cs: f32,
    #[serde(rename = "memoryOD")]
    pub memory_od: f32,
    #[serde(rename = "memoryHP")]
    pub memory_hp: f32,
    #[serde(rename = "fullSR")]
    pub full_sr: f32,
    // TODO: wtf does `json:"-"` mean? (do i need TotalHitObjects?)
}

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmapTime {
    // TODO: first_obj, full_time and mp3_time are used for oppai, do i really need to support this? (if so, how?)
    #[serde(rename = "current")]
    pub play_time: i32,
}

#[derive(Serialize, Deserialize)]
pub struct GosumemoryBeatmap {
    pub time: GosumemoryBeatmapTime,
    pub id: i32,
    pub set: i32,
    pub md5: String,
    #[serde(rename = "rankedStatus")]
    pub ranked_status: i32,
    pub metadata: GosumemoryBeatmapMetadata,
    pub stats: GosumemoryBeatmapStats,
    // TODO: path
    // TODO: wtf does `json:"-"` mean? (do i need HitObjectStats and BeatmapString?)
}
