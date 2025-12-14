mod http_api;
mod mongo;

use dotenvy::dotenv;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // تحميل متغيرات البيئة من .env (محليًا أو على Render إذا وفرتها)
    dotenv().ok();

    // تهيئة MongoDB
    mongo::init_mongo_from_env().await?;

    // تشغيل سيرفر الـ HTTP (Axum)
    http_api::run_http_server().await?;

    Ok(())
}
