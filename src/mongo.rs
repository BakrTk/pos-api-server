use mongodb::{
    bson::{doc, Document},
    options::{FindOptions, IndexOptions},
    Client, Database, IndexModel,
};
use once_cell::sync::OnceCell;
use anyhow::{Result, anyhow};

/// تخزين الـ Database بشكل ثابت (Singleton)
static MONGO_DB: OnceCell<Database> = OnceCell::new();

/// دالة الوصول إلى الـ Database بعد التهيئة
pub fn db() -> Result<&'static Database, String> {
    MONGO_DB
        .get()
        .ok_or_else(|| "MongoDB not initialized".to_string())
}

/// كشف إن كان الـ URI يشير إلى Firestore Mongo API
fn is_firestore_uri(uri: &str) -> bool {
    uri.contains(".firestore.goog")
}

/// تهيئة MongoDB من متغيرات البيئة:
/// - MONGO_URI (إجباري)
/// - MONGO_DB (اختياري، الافتراضي "default")
pub async fn init_mongo_from_env() -> Result<()> {
    // نحاول تحميل .env من مجلد المشروع (لو موجود)
    let _ = dotenvy::dotenv();

    let uri = std::env::var("MONGO_URI")
        .map_err(|_| anyhow!("MONGO_URI missing in environment"))?;

    let client = Client::with_uri_str(&uri)
        .await
        .map_err(|e| anyhow!("Mongo connect error: {}", e))?;

    let dbname = std::env::var("MONGO_DB").unwrap_or_else(|_| "default".into());
    let database = client.database(&dbname);

    let on_firestore = is_firestore_uri(&uri);

    // إنشاء الفهارس (indexes) – تُتخطى لو نستخدم Firestore Mongo API
    ensure_indexes(&database, on_firestore)
        .await
        .map_err(|e| anyhow!(e))?;

    // تخزين الـ Database في OnceCell
    MONGO_DB
        .set(database)
        .map_err(|_| anyhow!("MongoDB already initialized"))?;

    Ok(())
}

/// خيار فرز افتراضي: الأحدث أولاً حسب created_at ثم _id
pub fn sort_created_at_desc() -> FindOptions {
    FindOptions::builder()
        .sort(doc! { "created_at": -1, "_id": -1 })
        .build()
}

/// إنشاء الفهارس (indexes) على المجموعات الأساسية
async fn ensure_indexes(db: &Database, on_firestore: bool) -> Result<(), String> {
    if on_firestore {
        // في حال استخدام Mongo API فوق Firestore، نتجنب إنشاء فهارس خاصة
        return Ok(());
    }

    // items: index على الباركود
    let items = db.collection::<Document>("items");
    let idx_barcode = IndexModel::builder()
        .keys(doc! { "barcode": 1 })
        .options(IndexOptions::builder().name(Some("idx_barcode".into())).build())
        .build();
    let _ = items.create_index(idx_barcode, None).await;

    // categories: اسم فريد
    let categories = db.collection::<Document>("categories");
    let uniq_cat_name = IndexModel::builder()
        .keys(doc! { "name": 1 })
        .options(
            IndexOptions::builder()
                .unique(true)
                .name(Some("uniq_categories_name".into()))
                .build(),
        )
        .build();
    let _ = categories.create_index(uniq_cat_name, None).await;

    // admins: username فريد
    let admins = db.collection::<Document>("admins");
    let uniq_admin_username = IndexModel::builder()
        .keys(doc! { "username": 1 })
        .options(
            IndexOptions::builder()
                .unique(true)
                .name(Some("uniq_admin_username".into()))
                .build(),
        )
        .build();
    let _ = admins.create_index(uniq_admin_username, None).await;

    Ok(())
}
