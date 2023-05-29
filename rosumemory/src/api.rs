use std::sync::Arc;

use rosumemory_lib::{
    memory::pattern, memory::read::read_ptr, models::beatmap::Beatmap, osu::find_songs_folder,
    process::find_osu_process_id,
};
use springtime::application;
use springtime_di::{
    component_alias,
    future::{BoxFuture, FutureExt},
    injectable,
    instance_provider::{ComponentInstancePtr, ErrorPtr},
    Component,
};
use springtime_web_axum::{
    axum::Json,
    config::{ServerConfig, WebConfig, WebConfigProvider, DEFAULT_SERVER_NAME},
    controller,
};

use crate::{
    context::Context,
    models::gosumemory::{
        beatmap::{GosumemoryBeatmap, GosumemoryBeatmapMetadata},
        Gosumemory, GosumemoryMenu,
    },
};

#[derive(Component)]
#[component(constructor = "ConfigProvider::new")]
struct ConfigProvider {
    #[component(ignore)]
    config: WebConfig,
}

impl ConfigProvider {
    fn new() -> BoxFuture<'static, Result<Self, ErrorPtr>> {
        async {
            let mut web_config = WebConfig::default();
            let mut server_config = ServerConfig::default();

            // TODO: config, some people might not be using default gosumemory port
            let server_port = 24050;
            server_config.listen_address = format!("127.0.0.1:{server_port}");

            web_config
                .servers
                .insert(DEFAULT_SERVER_NAME.to_string(), server_config);

            Ok(Self { config: web_config })
        }
        .boxed()
    }
}

#[component_alias]
impl WebConfigProvider for ConfigProvider {
    fn config(&self) -> BoxFuture<'_, Result<&WebConfig, ErrorPtr>> {
        async { Ok(&self.config) }.boxed()
    }
}

#[injectable]
trait MemoryService {
    fn get_osu_pid(&self) -> usize;
    fn get_base_address(&self) -> usize;
    fn get_beatmap_ptr(&self) -> usize;
}

#[derive(Component)]
struct MemoryServiceImpl {
    #[component(default = "create_context")]
    ctx: Arc<Context>,
}

#[component_alias]
impl MemoryService for MemoryServiceImpl {
    fn get_osu_pid(&self) -> usize {
        self.ctx.osu_pid
    }

    fn get_base_address(&self) -> usize {
        self.ctx.base_address
    }

    fn get_beatmap_ptr(&self) -> usize {
        self.ctx.beatmap_ptr
    }
}

#[derive(Component)]
struct GosumemoryController {
    service: ComponentInstancePtr<dyn MemoryService + Send + Sync>,
}

#[controller]
impl GosumemoryController {
    #[get("/json")]
    async fn gosumemory_json(&self) -> Json<Gosumemory> {
        let osu_pid = self.service.get_osu_pid();
        let beatmap_ptr = self.service.get_beatmap_ptr();

        let beatmap = unsafe {
            Beatmap::from_ptr(osu_pid, beatmap_ptr as *mut u8)
                .expect("failed to retrieve beatmap from ptr")
        };

        Json(Gosumemory {
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
        })
    }
}

// no error handling here, they have already been tried before entering the api
// this still kind of sucks tho, there must be a better way to do this DI
// without globals / lazy statics
fn create_context() -> Arc<Context> {
    let osu_pid = find_osu_process_id().unwrap();

    let osu_songs_folder = find_songs_folder().unwrap();

    let base_addr = pattern::find_pattern(osu_pid, "F8 01 74 04 83 65").unwrap();

    let beatmap_ptr = unsafe { read_ptr(osu_pid, base_addr.sub(0xC) as usize).unwrap() };

    let context = Context::new(
        osu_pid.into(),
        osu_songs_folder,
        base_addr as usize,
        beatmap_ptr as usize,
    );
    Arc::new(context)
}

pub async fn serve() -> anyhow::Result<()> {
    let mut application = application::create_default().expect("unable to create application");
    application.run().await.expect("error running api");

    Ok(())
}
