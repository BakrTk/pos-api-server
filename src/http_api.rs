use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Path, Query, State},
    http::{Method, Request, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},  
    Json, Router,
};

use futures_util::TryStreamExt;
use hmac::{Hmac, Mac};
use mongodb::{
    bson::{doc, Bson, Document},
    Collection, Database,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use crate::mongo::db;

/* ================== Logging ================== */

fn now_iso_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn log_app(msg: &str) {
    println!("[{}] {}", now_iso_rfc3339(), msg);
}

/* ================== Context ================== */

#[derive(Clone)]
pub struct ApiCtx {
    pub api_key: String,
    pub hmac_secret: String,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}
impl From<String> for ApiError {
    fn from(e: String) -> Self {
        ApiError { error: e }
    }
}

#[derive(Serialize)]
struct OkMsg {
    ok: bool,
}

/* ================== Utilities ================== */

fn f64_from(d: &Document, k: &str) -> f64 {
    d.get_f64(k)
        .ok()
        .or_else(|| d.get_i64(k).ok().map(|v| v as f64))
        .or_else(|| d.get_i32(k).ok().map(|v| v as f64))
        .or_else(|| {
            d.get_str(k)
                .ok()
                .and_then(|s| s.trim().parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

fn opt_string(d: &Document, k: &str) -> Option<String> {
    d.get_str(k).ok().map(|s| s.to_string())
}

fn bool_from(d: &Document, k: &str) -> Option<bool> {
    if let Ok(b) = d.get_bool(k) {
        return Some(b);
    }
    if let Ok(i) = d.get_i32(k) {
        return Some(i != 0);
    }
    if let Ok(i) = d.get_i64(k) {
        return Some(i != 0);
    }
    if let Ok(s) = d.get_str(k) {
        let s = s.trim().to_ascii_lowercase();
        return match s.as_str() {
            "1" | "true" | "yes" | "y" => Some(true),
            "0" | "false" | "no" | "n" => Some(false),
            _ => None,
        };
    }
    None
}

fn id_filter(id: &str) -> Document {
    doc! { "$or": [ { "id": id }, { "_id": id } ] }
}

/* ================== Models (HTTP فقط) ================== */

/* ---- Admin ---- */

#[derive(Serialize, Deserialize, Clone)]
struct AdminDto {
    pub id: String,
    pub name: String,
    pub username: String,
    pub phone: Option<String>,
    pub role: String,
    pub created_at: String,
}

/* ---- User ---- */

#[derive(Serialize, Deserialize, Clone)]
struct UserDto {
    pub id: String,
    pub name: String,
    pub phone: Option<String>,
    pub date: Option<String>,
    pub role: Option<String>,
    pub created_at: Option<String>,
    pub note: Option<String>,
}

/* ---- Category ---- */

#[derive(Serialize, Deserialize, Clone)]
struct CategoryDto {
    pub id: String,
    pub name: String,
    pub created_at: Option<String>,
}

/* ---- Products (Ledger movements) ---- */

#[derive(Serialize, Deserialize, Clone)]
struct ProductsDto {
    pub id: String,
    pub note: Option<String>,
    pub transaction_type: String,
    pub price: f64,
    pub currency: String,
    pub user_id: String,
    pub created_at: String,
}

/* ---- Item ---- */

#[derive(Serialize, Deserialize, Clone)]
struct ItemDto {
    pub id: String,
    pub name: String,
    pub barcode: Option<String>,
    pub sell_price: Option<f64>,
    pub puch_price: Option<f64>,
    pub is_countable: Option<bool>,
    pub quantity: Option<f64>,
    pub category_id: Option<String>,
    pub note: Option<String>,
    pub printer_tag: Option<String>,
    pub image_url: Option<String>,
    pub created_at: Option<String>,
}

/* ---- Invoice ---- */

#[derive(Serialize, Deserialize, Clone)]
struct InvoiceDto {
    pub id: String,
    pub role: String,
    pub user_id: String,
    pub date: String,
    pub total_amount: f64,
    pub amount_paid: f64,
    pub remaining_amount: f64,
    pub discount: f64,
    pub movement_id: Option<String>,
    pub created_by: Option<String>,
    pub status: String,
    pub table_id: Option<String>,
    pub pay_method: Option<String>,
    pub created_at: String,
}

/* ---- InvoiceDetail ---- */

#[derive(Serialize, Deserialize, Clone)]
struct InvoiceDetailDto {
    pub id: String,
    pub invoice_id: String,
    pub item_id: String,
    pub price: f64,
    pub quantity: f64,
    pub total: f64,
    pub item_name: Option<String>,
    pub section: Option<String>,
    pub note: Option<String>,
}

/* ---- BoxData ---- */

#[derive(Serialize, Deserialize, Clone)]
struct BoxDataDto {
    pub id: String,
    pub note: Option<String>,
    pub price: f64,
    pub type_field: String, // "in" / "out"  ← نفس Tauri
    pub created_at: String,
    pub currency: String,
}



/* ---- Profit ---- */

#[derive(Serialize, Deserialize, Clone)]
struct ProfitDto {
    pub id: String,
    pub note: Option<String>,
    pub amount: f64,
    pub profit_type: String,
    pub date: String,
}

/* ---- Supplier ---- */

#[derive(Serialize, Deserialize, Clone)]
struct SupplierDto {
    pub id: String,
    pub name: String,
    pub phone: Option<String>,
    pub note: Option<String>,
    pub created_at: Option<String>,
}

/* ---- SupplierInvoice ---- */

#[derive(Serialize, Deserialize, Clone)]
struct SupplierInvoiceDto {
    pub id: String,
    pub supplier_id: String,
    pub invoice_id: Option<String>,
    pub amount: f64,
    pub created_at: Option<String>,
}

/* ---- Table ---- */

#[derive(Serialize, Deserialize, Clone)]
struct TableDto {
    pub id: String,
    pub name: String,
    pub capacity: Option<i64>,
    pub status: Option<String>,
    pub current_invoice_id: Option<String>,
    pub created_at: Option<String>,
}

/* ================== Auth Middleware ================== */

async fn auth_mw(
    State(ctx): State<Arc<ApiCtx>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    log_app(&format!("HTTP {} {}", req.method(), req.uri().path()));

    if req.method() == Method::OPTIONS {
        log_app("-> OPTIONS preflight, skipping auth");
        return Ok(next.run(req).await);
    }

    let api_key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if api_key != ctx.api_key {
        log_app("-> Unauthorized (bad API key)");
        return Err(Json(ApiError::from("Unauthorized (API key)".to_string())).into_response());
    }

    let sig_opt = req
        .headers()
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(sig) = sig_opt {
        log_app(&format!("-> X-Signature present ({:.8}…)", sig));

        let owned: Body = std::mem::take(req.body_mut());
        let bytes = to_bytes(owned, 1_048_576)
            .await
            .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;

        let mut mac = Hmac::<Sha256>::new_from_slice(ctx.hmac_secret.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

        mac.update(&bytes);
        let expected = hex::encode(mac.finalize().into_bytes());

        if expected != sig {
            log_app(&format!(
                "-> Invalid signature expected={} got={}",
                expected, sig
            ));
            return Err(Json(ApiError::from("Invalid signature".to_string())).into_response());
        }

        let (parts, _) = req.into_parts();
        req = Request::from_parts(parts, Body::from(bytes));
    }

    Ok(next.run(req).await)
}

/* ================== DTOs للطلبات ================== */

/* ---- Admin ---- */

use argon2::{
    password_hash::{PasswordHash, PasswordVerifier, PasswordHasher, SaltString},
    Argon2,
};
use argon2::password_hash::rand_core::OsRng;

#[derive(Deserialize)]
struct AdminCreateReq {
    pub name: String,
    pub username: String,
    pub phone: Option<String>,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize)]
struct AdminUpdateReq {
    pub name: Option<String>,
    pub username: Option<String>,
    pub phone: Option<String>,
    pub password: Option<String>,
    pub role: Option<String>,
}

/* ---- User ---- */

#[derive(Deserialize)]
struct UserCreateReq {
    pub name: String,
    pub phone: Option<String>,
    pub date: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
}

#[derive(Deserialize)]
struct UserUpdateReq {
    pub name: Option<String>,
    pub phone: Option<String>,
    pub date: Option<String>,
    pub role: Option<String>,
    pub note: Option<String>,
}

/* ---- Category ---- */

#[derive(Deserialize)]
struct CategoryCreateReq {
    pub name: String,
}

#[derive(Deserialize)]
struct CategoryUpdateReq {
    pub name: Option<String>,
}

/* ---- Items ---- */

#[derive(Deserialize)]
struct ItemsQuery {
    section: Option<String>,
}

#[derive(Deserialize)]
struct ItemCreateReq {
    pub name: String,
    pub barcode: Option<String>,
    pub sell_price: Option<f64>,
    pub puch_price: Option<f64>,
    pub is_countable: Option<bool>,
    pub quantity: Option<f64>,
    pub category_id: Option<String>,
    pub note: Option<String>,
    pub printer_tag: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Deserialize)]
struct ItemUpdateReq {
    pub name: Option<String>,
    pub barcode: Option<String>,
    pub sell_price: Option<f64>,
    pub puch_price: Option<f64>,
    pub is_countable: Option<bool>,
    pub quantity: Option<f64>,
    pub category_id: Option<String>,
    pub note: Option<String>,
    pub printer_tag: Option<String>,
    pub image_url: Option<String>,
}

/* ---- Tables ---- */

#[derive(Deserialize)]
struct AddTableReq {
    name: String,
    capacity: Option<i64>,
}

#[derive(Deserialize)]
struct TableUpdateReq {
    pub name: Option<String>,
    pub capacity: Option<i64>,
    pub status: Option<String>,
}

/* ---- Invoice open/pay/add/dec/move ---- */

#[derive(Deserialize)]
struct OpenInvoiceReq {
    table_id: String,
    operator_name: String,
}

#[derive(Serialize)]
struct OpenInvoiceResp {
    invoice: InvoiceDto,
}

#[derive(Deserialize)]
struct AddIncReq {
    item_id: String,
    quantity: f64,
    price: f64,
    item_name: Option<String>,
    section: Option<String>,
    note: Option<String>,
}

#[derive(Deserialize)]
struct DecReq {
    item_id: String,
    dec_qty: f64,
}

#[derive(Deserialize)]
struct PayReq {
    discount: f64,
    amount_paid: f64,
    pay_method: String,
    operator_name: String,
}

#[derive(Deserialize)]
struct MoveInvoiceReq {
    invoice_id: String,
    from_table_id: String,
    to_table_id: String,
}

/* ---- Products query ---- */

#[derive(Deserialize)]
struct ProductsQuery {
    user_id: Option<String>,
}

/* ---- SupplierInvoice query ---- */

#[derive(Deserialize)]
struct SupplierInvoicesQuery {
    supplier_id: Option<String>,
}

/* ================== Low-level helpers ================== */

fn inv_to_doc(i: &InvoiceDto) -> Document {
    let mut d = Document::new();
    d.insert("_id", i.id.clone());
    d.insert("id", i.id.clone());
    d.insert("role", i.role.clone());
    d.insert("user_id", i.user_id.clone());
    d.insert("date", i.date.clone());
    d.insert("total_amount", Bson::from(i.total_amount));
    d.insert("amount_paid", Bson::from(i.amount_paid));
    d.insert("remaining_amount", Bson::from(i.remaining_amount));
    d.insert("discount", Bson::from(i.discount));
    d.insert("status", i.status.clone());
    d.insert(
        "pay_method",
        i.pay_method
            .clone()
            .map(Bson::String)
            .unwrap_or(Bson::Null),
    );
    d.insert(
        "table_id",
        i.table_id.clone().map(Bson::String).unwrap_or(Bson::Null),
    );
    d.insert(
        "movement_id",
        i.movement_id
            .clone()
            .map(Bson::String)
            .unwrap_or(Bson::Null),
    );
    d.insert(
        "created_by",
        i.created_by
            .clone()
            .map(Bson::String)
            .unwrap_or(Bson::Null),
    );
    d.insert("created_at", i.created_at.clone());
    d
}

fn doc_to_inv(d: Document) -> InvoiceDto {
    InvoiceDto {
        id: d
            .get_str("id")
            .or_else(|_| d.get_str("_id"))
            .unwrap_or_default()
            .to_string(),
        role: d.get_str("role").unwrap_or_default().to_string(),
        user_id: d.get_str("user_id").unwrap_or_default().to_string(),
        date: d.get_str("date").unwrap_or_default().to_string(),
        total_amount: f64_from(&d, "total_amount"),
        amount_paid: f64_from(&d, "amount_paid"),
        remaining_amount: f64_from(&d, "remaining_amount"),
        discount: f64_from(&d, "discount"),
        movement_id: opt_string(&d, "movement_id"),
        created_by: opt_string(&d, "created_by"),
        status: d.get_str("status").unwrap_or("open").to_string(),
        table_id: opt_string(&d, "table_id"),
        pay_method: opt_string(&d, "pay_method"),
        created_at: d
            .get_str("created_at")
            .ok()
            .map(|s| s.to_string())
            .unwrap_or_else(now_iso_rfc3339),
    }
}

fn invdet_to_doc(x: &InvoiceDetailDto) -> Document {
    let mut d = Document::new();
    d.insert("_id", x.id.clone());
    d.insert("id", x.id.clone());
    d.insert("invoice_id", x.invoice_id.clone());
    d.insert("item_id", x.item_id.clone());
    d.insert("price", Bson::from(x.price));
    d.insert("quantity", Bson::from(x.quantity));
    d.insert("total", Bson::from(x.total));
    if let Some(n) = &x.item_name {
        d.insert("item_name", n.clone());
    }
    if let Some(s) = &x.section {
        d.insert("section", s.clone());
    }
    if let Some(note) = &x.note {
        d.insert("note", note.clone());
    }
    d
}

/* ====== movements helpers (Mongo products) ====== */

fn movement_note_prefix(role: &str, remaining: f64) -> Option<&'static str> {
    match role {
        "1" => {
            if remaining > 0.0 {
                Some("متبقي فاتورة مبيعات")
            } else if remaining < 0.0 {
                Some("رصيد دائن (زيادة دفع) لفاتورة مبيعات")
            } else {
                None
            }
        }
        "2" => {
            if remaining > 0.0 {
                Some("متبقي فاتورة مشتريات")
            } else if remaining < 0.0 {
                Some("رصيد لنا لدى المورد (زيادة دفع) لفاتورة مشتريات")
            } else {
                None
            }
        }
        "3" => {
            if remaining > 0.0 {
                Some("متبقي فاتورة راجع (للعميل)")
            } else if remaining < 0.0 {
                Some("متبقي فاتورة راجع بالسالب")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn movement_tx_type(role: &str, remaining: f64) -> Option<&'static str> {
    if remaining == 0.0 {
        return None;
    }
    match role {
        "1" => Some(if remaining > 0.0 { "1" } else { "2" }),
        "2" => Some(if remaining > 0.0 { "2" } else { "1" }),
        "3" => Some(if remaining > 0.0 { "2" } else { "1" }),
        _ => None,
    }
}

async fn upsert_movement_mongo(
    db: &Database,
    movement_id: Option<String>,
    user_id: &str,
    date: &str,
    role: &str,
    invoice_id: &str,
    remaining_amount: f64,
) -> Result<Option<String>, String> {
    let coll = db.collection::<Document>("products");

    if remaining_amount == 0.0 {
        if let Some(mv_id) = movement_id {
            let _ = coll
                .delete_one(doc! { "_id": &mv_id }, None)
                .await
                .map_err(|e| format!("Mongo delete movement error: {e}"))?;
        }
        return Ok(None);
    }

    let tx_type = movement_tx_type(role, remaining_amount)
        .ok_or_else(|| "تعذر تحديد نوع الحركة".to_string())?;
    let prefix = movement_note_prefix(role, remaining_amount).unwrap_or("رصيد فاتورة");
    let amount = remaining_amount.abs();
    let note = format!("{prefix} {inv}", prefix = prefix, inv = invoice_id);

    let new_doc = doc! {
        "note": note,
        "transaction_type": tx_type,
        "price": Bson::from(amount),
        "currency": "IQD",
        "user_id": user_id,
        "created_at": date,
    };

    match movement_id {
        Some(mv_id) => {
            coll.update_one(doc! { "_id": &mv_id }, doc! { "$set": new_doc }, None)
                .await
                .map_err(|e| format!("Mongo update movement error: {e}"))?;
            Ok(Some(mv_id))
        }
        None => {
            let new_id = Uuid::new_v4().to_string();
            let mut ins = new_doc.clone();
            ins.insert("_id", new_id.clone());
            ins.insert("id", new_id.clone());
            coll.insert_one(ins, None)
                .await
                .map_err(|e| format!("Mongo insert movement error: {e}"))?;
            Ok(Some(new_id))
        }
    }
}

async fn recalc_and_update_totals(
    db: &Database,
    invoice_id: &str,
) -> Result<(f64, f64, f64), String> {
    let det = db.collection::<Document>("invoice_details");
    let mut cur = det
        .find(doc! { "invoice_id": invoice_id }, None)
        .await
        .map_err(|e| format!("Mongo find details error: {e}"))?;
    let mut total = 0.0;
    while let Some(d) = cur.try_next().await.map_err(|e| e.to_string())? {
        total += f64_from(&d, "total");
    }

    let inv_coll = db.collection::<Document>("invoices");
    let inv_doc = inv_coll
        .find_one(doc! { "_id": invoice_id }, None)
        .await
        .map_err(|e| format!("Mongo find_one invoice error: {e}"))?
        .ok_or_else(|| "الفاتورة غير موجودة".to_string())?;

    let mut inv = doc_to_inv(inv_doc);

    inv.total_amount = (total * 1000.0).round() / 1000.0;
    inv.remaining_amount = (inv.total_amount - inv.amount_paid).round();

    let new_movement = upsert_movement_mongo(
        db,
        inv.movement_id.clone(),
        &inv.user_id,
        &inv.date,
        &inv.role,
        &inv.id,
        inv.remaining_amount,
    )
    .await?;

    inv_coll
        .update_one(
            doc! { "_id": &inv.id },
            doc! { "$set": {
                "total_amount": Bson::from(inv.total_amount),
                "remaining_amount": Bson::from(inv.remaining_amount),
                "movement_id": new_movement.clone().map(Bson::String).unwrap_or(Bson::Null),
            }},
            None,
        )
        .await
        .map_err(|e| format!("Mongo update invoice totals error: {e}"))?;

    Ok((inv.total_amount, inv.amount_paid, inv.remaining_amount))
}

async fn apply_stock_for_invoice(db: &Database, inv: &InvoiceDto) -> Result<(), String> {
    if inv.role != "1" || inv.table_id.is_none() {
        return Ok(());
    }

    let det = db.collection::<Document>("invoice_details");
    let items = db.collection::<Document>("items");

    let mut cur = det
        .find(doc! { "invoice_id": &inv.id }, None)
        .await
        .map_err(|e| format!("Mongo find invoice_details error: {e}"))?;

    while let Some(d) = cur.try_next().await.map_err(|e| e.to_string())? {
        let item_id = d.get_str("item_id").unwrap_or_default().to_string();
        let qty = f64_from(&d, "quantity");
        if qty <= 0.0 {
            continue;
        }
        if let Some(i) = items
            .find_one(doc! { "_id": &item_id }, None)
            .await
            .map_err(|e| e.to_string())?
        {
            let is_countable = i.get_bool("is_countable").unwrap_or(false);
            if !is_countable {
                continue;
            }
            items
                .update_one(
                    doc! { "_id": &item_id },
                    doc! { "$inc": { "quantity": Bson::from(-qty) } },
                    None,
                )
                .await
                .map_err(|e| format!("Mongo update item stock error: {e}"))?;
        }
    }

    Ok(())
}

/* ================== Events (بدل Tauri) ================== */

fn emit_all_compat(event: &str, payload: &serde_json::Value) {
    log_app(&format!("[EMIT] {event} => {payload}"));
}

/* ================== Routes: عامة / Health ================== */

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ok": true,
        "service": "mandoob-pos",
        "ts": now_iso_rfc3339()
    }))
}

/* ---- /api/login ---- */

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResp {
    ok: bool,
    name: String,
    role: String,
    token: String,
}

async fn login(Json(req): Json<LoginReq>) -> Result<Json<LoginResp>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let admins: Collection<Document> = database.collection("admins");

    let admin = admins
        .find_one(doc! { "username": &req.username }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| {
            Json(ApiError {
                error: "Invalid credentials".into(),
            })
            .into_response()
        })?;

    let stored_hash = admin.get_str("password").unwrap_or("");
    let parsed = PasswordHash::new(stored_hash).map_err(|_| {
        Json(ApiError {
            error: "Invalid credentials".into(),
        })
        .into_response()
    })?;

    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .map_err(|_| {
            Json(ApiError {
                error: "Invalid credentials".into(),
            })
            .into_response()
        })?;

    let token = Uuid::new_v4().to_string();
    let name = admin.get_str("name").unwrap_or("User").to_string();
    let role = admin.get_str("role").unwrap_or("user").to_string();

    Ok(Json(LoginResp {
        ok: true,
        name,
        role,
        token,
    }))
}

/* ================== Admins CRUD ================== */

async fn admins_list() -> Result<Json<Vec<AdminDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("admins");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(AdminDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: docu.get_str("name").unwrap_or_default().to_string(),
            username: docu.get_str("username").unwrap_or_default().to_string(),
            phone: opt_string(&docu, "phone"),
            role: docu.get_str("role").unwrap_or("user").to_string(),
            created_at: docu
                .get_str("created_at")
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(now_iso_rfc3339),
        });
    }

    Ok(Json(out))
}

async fn admin_add(Json(req): Json<AdminCreateReq>) -> Result<Json<AdminDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("admins");

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso_rfc3339();

    let salt = SaltString::generate(&mut OsRng);
    let argon = Argon2::default();
    let hash = argon
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|_| {
            Json(ApiError {
                error: "Failed to hash password".into(),
            })
            .into_response()
        })?
        .to_string();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "username": &req.username,
        "phone": req.phone.clone().map(Bson::String).unwrap_or(Bson::Null),
        "password": hash,
        "role": &req.role,
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(AdminDto {
        id,
        name: req.name,
        username: req.username,
        phone: req.phone,
        role: req.role,
        created_at,
    }))
}

async fn admin_update(
    Path(id): Path<String>,
    Json(req): Json<AdminUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("admins");

    let mut set_doc = Document::new();

    if let Some(name) = req.name {
        set_doc.insert("name", name);
    }
    if let Some(username) = req.username {
        set_doc.insert("username", username);
    }
    if let Some(phone) = req.phone {
        set_doc.insert("phone", phone);
    }
    if let Some(role) = req.role {
        set_doc.insert("role", role);
    }
    if let Some(pass) = req.password {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(pass.as_bytes(), &salt)
            .map_err(|_| {
                Json(ApiError {
                    error: "Failed to hash password".into(),
                })
                .into_response()
            })?
            .to_string();
        set_doc.insert("password", hash);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn admin_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("admins");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Users CRUD ================== */

async fn users_list() -> Result<Json<Vec<UserDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("users");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(UserDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: docu.get_str("name").unwrap_or_default().to_string(),
            phone: opt_string(&docu, "phone"),
            date: opt_string(&docu, "date"),
            role: opt_string(&docu, "role"),
            created_at: opt_string(&docu, "created_at"),
            note: opt_string(&docu, "note"),
        });
    }

    Ok(Json(out))
}

async fn user_add(Json(req): Json<UserCreateReq>) -> Result<Json<UserDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("users");

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso_rfc3339();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "phone": req.phone.clone().map(Bson::String).unwrap_or(Bson::Null),
        "date": req.date.clone().map(Bson::String).unwrap_or(Bson::Null),
        "role": req.role.clone().map(Bson::String).unwrap_or(Bson::Null),
        "created_at": &created_at,
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(UserDto {
        id,
        name: req.name,
        phone: req.phone,
        date: req.date,
        role: req.role,
        created_at: Some(created_at),
        note: req.note,
    }))
}

async fn user_update(
    Path(id): Path<String>,
    Json(req): Json<UserUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("users");

    let mut set_doc = Document::new();
    if let Some(name) = req.name {
        set_doc.insert("name", name);
    }
    if let Some(phone) = req.phone {
        set_doc.insert("phone", phone);
    }
    if let Some(date) = req.date {
        set_doc.insert("date", date);
    }
    if let Some(role) = req.role {
        set_doc.insert("role", role);
    }
    if let Some(note) = req.note {
        set_doc.insert("note", note);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn user_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("users");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Categories CRUD ================== */

async fn categories_list() -> Result<Json<Vec<CategoryDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("categories");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];

    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(CategoryDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: docu.get_str("name").unwrap_or_default().to_string(),
            created_at: opt_string(&docu, "created_at"),
        });
    }

    Ok(Json(out))
}

async fn category_add(Json(req): Json<CategoryCreateReq>) -> Result<Json<CategoryDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("categories");

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso_rfc3339();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(CategoryDto {
        id,
        name: req.name,
        created_at: Some(created_at),
    }))
}

async fn category_update(
    Path(id): Path<String>,
    Json(req): Json<CategoryUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("categories");

    let mut set_doc = Document::new();
    if let Some(name) = req.name {
        set_doc.insert("name", name);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn category_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("categories");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Items CRUD (مع ?section) ================== */

async fn items_list(Query(q): Query<ItemsQuery>) -> Result<Json<Vec<ItemDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("items");

    let mut filter = doc! {};
    if let Some(sec) = q.section.as_ref().map(|s| s.trim().to_string()) {
        if !sec.is_empty() && sec.to_ascii_lowercase() != "all" && sec != "*" {
            filter = doc! { "$or": [
                { "printer_tag": &sec },
                { "category_name": &sec },
            ]};
        }
    }

    let mut cur = coll
        .find(filter, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];

    while let Some(doc) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(ItemDto {
            id: doc
                .get_str("id")
                .or_else(|_| doc.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: doc.get_str("name").unwrap_or_default().to_string(),
            barcode: opt_string(&doc, "barcode"),
            sell_price: Some(f64_from(&doc, "sell_price")),
            puch_price: Some(f64_from(&doc, "puch_price")),
            is_countable: bool_from(&doc, "is_countable"),
            quantity: Some(f64_from(&doc, "quantity")),
            category_id: opt_string(&doc, "category_id"),
            note: opt_string(&doc, "note"),
            printer_tag: opt_string(&doc, "printer_tag"),
            image_url: opt_string(&doc, "image_url"),
            created_at: opt_string(&doc, "created_at"),
        });
    }

    Ok(Json(out))
}

async fn item_add(Json(req): Json<ItemCreateReq>) -> Result<Json<ItemDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("items");

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso_rfc3339();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "barcode": req.barcode.clone().map(Bson::String).unwrap_or(Bson::Null),
        "sell_price": req.sell_price.unwrap_or(0.0),
        "puch_price": req.puch_price.unwrap_or(0.0),
        "is_countable": req.is_countable.unwrap_or(false),
        "quantity": req.quantity.unwrap_or(0.0),
        "category_id": req.category_id.clone().map(Bson::String).unwrap_or(Bson::Null),
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
        "printer_tag": req.printer_tag.clone().map(Bson::String).unwrap_or(Bson::Null),
        "image_url": req.image_url.clone().map(Bson::String).unwrap_or(Bson::Null),
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(ItemDto {
        id,
        name: req.name,
        barcode: req.barcode,
        sell_price: req.sell_price,
        puch_price: req.puch_price,
        is_countable: req.is_countable,
        quantity: req.quantity,
        category_id: req.category_id,
        note: req.note,
        printer_tag: req.printer_tag,
        image_url: req.image_url,
        created_at: Some(created_at),
    }))
}

async fn item_update(
    Path(id): Path<String>,
    Json(req): Json<ItemUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("items");

    let mut set_doc = Document::new();

    if let Some(v) = req.name {
        set_doc.insert("name", v);
    }
    if let Some(v) = req.barcode {
        set_doc.insert("barcode", v);
    }
    if let Some(v) = req.sell_price {
        set_doc.insert("sell_price", v);
    }
    if let Some(v) = req.puch_price {
        set_doc.insert("puch_price", v);
    }
    if let Some(v) = req.is_countable {
        set_doc.insert("is_countable", v);
    }
    if let Some(v) = req.quantity {
        set_doc.insert("quantity", v);
    }
    if let Some(v) = req.category_id {
        set_doc.insert("category_id", v);
    }
    if let Some(v) = req.note {
        set_doc.insert("note", v);
    }
    if let Some(v) = req.printer_tag {
        set_doc.insert("printer_tag", v);
    }
    if let Some(v) = req.image_url {
        set_doc.insert("image_url", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn item_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("items");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Tables CRUD ================== */

async fn tables_list() -> Result<Json<Vec<TableDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("tables");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];

    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(TableDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: docu.get_str("name").unwrap_or_default().to_string(),
            capacity: docu.get_i64("capacity").ok(),
            status: opt_string(&docu, "status"),
            current_invoice_id: opt_string(&docu, "current_invoice_id"),
            created_at: opt_string(&docu, "created_at"),
        });
    }

    Ok(Json(out))
}

async fn table_add(Json(req): Json<AddTableReq>) -> Result<Json<TableDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("tables");

    let id = Uuid::new_v4().to_string();
    let created_at = now_iso_rfc3339();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "capacity": req.capacity.map(Bson::Int64).unwrap_or(Bson::Null),
        "status": "free",
        "current_invoice_id": Bson::Null,
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(TableDto {
        id,
        name: req.name,
        capacity: req.capacity,
        status: Some("free".into()),
        current_invoice_id: None,
        created_at: Some(created_at),
    }))
}

async fn table_update(
    Path(id): Path<String>,
    Json(req): Json<TableUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("tables");

    let mut set_doc = Document::new();
    if let Some(name) = req.name {
        set_doc.insert("name", name);
    }
    if let Some(cap) = req.capacity {
        set_doc.insert("capacity", Bson::Int64(cap));
    }
    if let Some(status) = req.status {
        set_doc.insert("status", status);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn table_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("tables");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Invoices: List/Get/Open/Details/Add/Dec/Void/Pay/Print/Move ================== */

async fn invoices_list() -> Result<Json<Vec<InvoiceDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("invoices");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(doc_to_inv(docu));
    }

    Ok(Json(out))
}

async fn invoice_get(Path(id): Path<String>) -> Result<Json<InvoiceDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("invoices");

    let inv_doc = coll
        .find_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| Json(ApiError::from("الفاتورة غير موجودة".to_string())).into_response())?;

    Ok(Json(doc_to_inv(inv_doc)))
}

async fn invoice_open(
    State(_ctx): State<Arc<ApiCtx>>,
    Json(req): Json<OpenInvoiceReq>,
) -> Result<Json<OpenInvoiceResp>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let tables: Collection<Document> = database.collection("tables");
    let invoices: Collection<Document> = database.collection("invoices");

    if let Some(t) = tables
        .find_one(doc! { "id": &req.table_id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        if let Ok(inv_id) = t.get_str("current_invoice_id") {
            if !inv_id.is_empty() {
                if let Some(inv) = invoices
                    .find_one(doc! { "_id": inv_id }, None)
                    .await
                    .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
                {
                    return Ok(Json(OpenInvoiceResp {
                        invoice: doc_to_inv(inv),
                    }));
                }
            }
        }
    }

    let id = format!("INV-{}", Uuid::new_v4());
    let now = now_iso_rfc3339();

    let new_inv = InvoiceDto {
        id: id.clone(),
        role: "1".into(),
        user_id: "cash".into(),
        date: now.clone(),
        total_amount: 0.0,
        amount_paid: 0.0,
        remaining_amount: 0.0,
        discount: 0.0,
        movement_id: None,
        created_by: None,
        status: "open".into(),
        table_id: Some(req.table_id.clone()),
        pay_method: None,
        created_at: now,
    };

    invoices
        .insert_one(inv_to_doc(&new_inv), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    tables
        .update_one(
            doc! { "id": &req.table_id },
            doc! { "$set": { "status":"occupied","current_invoice_id": &id } },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OpenInvoiceResp { invoice: new_inv }))
}

async fn invoice_move(
    Json(req): Json<MoveInvoiceReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let invoices: Collection<Document> = database.collection("invoices");
    let tables: Collection<Document> = database.collection("tables");

    // تأكد أن الفاتورة موجودة
    let inv_doc = invoices
        .find_one(doc! { "_id": &req.invoice_id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| Json(ApiError::from("الفاتورة غير موجودة".to_string())).into_response())?;

    let mut inv = doc_to_inv(inv_doc);

    // تحديث table_id في الفاتورة
    inv.table_id = Some(req.to_table_id.clone());
    invoices
        .update_one(
            doc! { "_id": &inv.id },
            doc! { "$set": { "table_id": &req.to_table_id } },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    // تحرير الطاولة القديمة إذا كانت تشير لهذه الفاتورة
    tables
        .update_one(
            doc! { "id": &req.from_table_id, "current_invoice_id": &inv.id },
            doc! { "$set": { "status": "free", "current_invoice_id": Bson::Null } },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    // ربط الفاتورة بالطاولة الجديدة
    tables
        .update_one(
            doc! { "id": &req.to_table_id },
            doc! { "$set": { "status": "occupied", "current_invoice_id": &inv.id } },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

async fn invoice_details(Path(id): Path<String>) -> Result<Json<Vec<InvoiceDetailDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let det: Collection<Document> = database.collection("invoice_details");

    let mut cur = det
        .find(doc! { "invoice_id": &id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];

    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(InvoiceDetailDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            invoice_id: docu
                .get_str("invoice_id")
                .unwrap_or_default()
                .to_string(),
            item_id: docu.get_str("item_id").unwrap_or_default().to_string(),
            price: (f64_from(&docu, "price") * 1000.0).round() / 1000.0,
            quantity: (f64_from(&docu, "quantity") * 1000.0).round() / 1000.0,
            total: (f64_from(&docu, "total") * 1000.0).round() / 1000.0,
            item_name: opt_string(&docu, "item_name"),
            section: opt_string(&docu, "section"),
            note: opt_string(&docu, "note"),
        });
    }

    Ok(Json(out))
}

async fn invoice_add_or_inc(
    Path(id): Path<String>,
    Json(req): Json<AddIncReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let det: Collection<Document> = database.collection("invoice_details");

    if let Some(line) = det
        .find_one(doc! { "invoice_id": &id, "item_id": &req.item_id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        let qty_old = f64_from(&line, "quantity");
        let existing_price = f64_from(&line, "price");
        let price = existing_price.max(req.price);
        let qty_new = qty_old + req.quantity;
        let total = (price * qty_new * 1000.0).round() / 1000.0;

        let mut set_doc = doc! { "quantity": qty_new, "price": price, "total": total };
        if let Some(n) = req.item_name.as_ref() {
            set_doc.insert("item_name", n.clone());
        }
        if let Some(s) = req.section.as_ref() {
            set_doc.insert("section", s.clone());
        }
        if let Some(note) = req.note.as_ref() {
            set_doc.insert("note", note.clone());
        }

        det.update_one(
            doc! { "id": line.get_str("id").or_else(|_| line.get_str("_id")).unwrap_or_default() },
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    } else {
        let row_id = Uuid::new_v4().to_string();
        let price = req.price;
        let total = (price * req.quantity * 1000.0).round() / 1000.0;

        let mut docu = doc! {
            "_id": &row_id,
            "id": &row_id,
            "invoice_id": &id,
            "item_id": &req.item_id,
            "price": price,
            "quantity": req.quantity,
            "total": total
        };
        if let Some(n) = req.item_name {
            docu.insert("item_name", n);
        }
        if let Some(s) = req.section {
            docu.insert("section", s);
        }
        if let Some(note) = req.note {
            docu.insert("note", note);
        }

        det.insert_one(docu, None)
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    let _ = recalc_and_update_totals(&database, &id)
        .await
        .map_err(|e| Json(ApiError::from(e)).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

async fn invoice_decrement_or_remove(
    Path(id): Path<String>,
    Json(req): Json<DecReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let det: Collection<Document> = database.collection("invoice_details");

    if let Some(line) = det
        .find_one(doc! { "invoice_id": &id, "item_id": &req.item_id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        let qty_old = f64_from(&line, "quantity");
        let price = f64_from(&line, "price");
        let qty_new = qty_old - req.dec_qty;

        if qty_new <= 0.0 {
            det.delete_one(
                doc! {
                    "id": line
                        .get_str("id")
                        .or_else(|_| line.get_str("_id"))
                        .unwrap_or_default()
                },
                None,
            )
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
        } else {
            let total = (price * qty_new * 1000.0).round() / 1000.0;
            det.update_one(
                doc! { "id": line.get_str("id").or_else(|_| line.get_str("_id")).unwrap_or_default() },
                doc! { "$set": { "quantity": qty_new, "total": total } },
                None,
            )
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
        }

        let _ = recalc_and_update_totals(&database, &id)
            .await
            .map_err(|e| Json(ApiError::from(e)).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

/* ---- إلغاء الفاتورة ---- */

async fn invoice_close_void(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let invoices: Collection<Document> = database.collection("invoices");
    let tables: Collection<Document> = database.collection("tables");

    let inv_doc = invoices
        .find_one(doc! { "_id": &id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| Json(ApiError::from("الفاتورة غير موجودة".to_string())).into_response())?;

    let mut inv = doc_to_inv(inv_doc);

    inv.amount_paid = 0.0;
    inv.remaining_amount = 0.0;
    inv.status = "void".into();
    inv.pay_method = None;

    let _ = upsert_movement_mongo(
        &database,
        inv.movement_id.clone(),
        &inv.user_id,
        &inv.date,
        &inv.role,
        &inv.id,
        0.0,
    )
    .await
    .map_err(|e| Json(ApiError::from(e)).into_response())?;

    invoices
        .update_one(
            doc! { "_id": &inv.id },
            doc! { "$set": {
                "amount_paid": 0.0_f64,
                "remaining_amount": 0.0_f64,
                "status": "void",
                "pay_method": Bson::Null,
                "movement_id": Bson::Null
            }},
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    tables
        .update_many(
            doc! { "current_invoice_id": &inv.id },
            doc! { "$set": { "status": "free", "current_invoice_id": Bson::Null }},
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ---- pay & print ---- */

async fn invoice_pay_and_close(
    State(_ctx): State<Arc<ApiCtx>>,
    Path(id): Path<String>,
    Json(req): Json<PayReq>,
) -> Result<Json<OkMsg>, Response> {
    log_app(&format!(
        "invoice_pay_and_close start id={} op={}",
        id, req.operator_name
    ));

    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let invoices: Collection<Document> = database.collection("invoices");
    let tables: Collection<Document> = database.collection("tables");
    let details_coll = database.collection::<Document>("invoice_details");
    let items_coll = database.collection::<Document>("items");
    let cats_coll = database.collection::<Document>("categories");

    let inv_doc = invoices
        .find_one(doc! { "_id": &id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| Json(ApiError::from("الفاتورة غير موجودة".to_string())).into_response())?;

    let mut inv = doc_to_inv(inv_doc);
    let was_paid = inv.status == "paid";

    inv.discount = req.discount.max(0.0);
    inv.amount_paid = req.amount_paid.max(0.0);
    inv.remaining_amount = (inv.total_amount - inv.discount - inv.amount_paid).round();
    if inv.remaining_amount < 0.0 {
        inv.remaining_amount = 0.0;
    }
    inv.pay_method = Some(req.pay_method.clone());

    let now_paid = inv.remaining_amount <= 0.0;
    inv.status = if now_paid { "paid".into() } else { "open".into() };

    let new_movement = upsert_movement_mongo(
        &database,
        inv.movement_id.clone(),
        &inv.user_id,
        &inv.date,
        &inv.role,
        &inv.id,
        inv.remaining_amount,
    )
    .await
    .map_err(|e| Json(ApiError::from(e)).into_response())?;

    invoices
        .update_one(
            doc! { "_id": &inv.id },
            doc! { "$set": {
                "amount_paid": Bson::from(inv.amount_paid),
                "remaining_amount": Bson::from(inv.remaining_amount),
                "discount": Bson::from(inv.discount),
                "status": inv.status.clone(),
                "pay_method": inv
                    .pay_method
                    .clone()
                    .map(Bson::String)
                    .unwrap_or(Bson::Null),
                "movement_id": new_movement
                    .clone()
                    .map(Bson::String)
                    .unwrap_or(Bson::Null)
            }},
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    if now_paid && !was_paid {
        tables
            .update_many(
                doc! { "current_invoice_id": &inv.id },
                doc! { "$set": { "status": "free", "current_invoice_id": Bson::Null }},
                None,
            )
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

        apply_stock_for_invoice(&database, &inv)
            .await
            .map_err(|e| Json(ApiError::from(e)).into_response())?;
    }

    let mut table_name: Option<String> = None;
    if let Some(tid) = inv.table_id.clone() {
        if let Some(tdoc) = tables
            .find_one(doc! { "id": &tid }, None)
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        {
            table_name = tdoc.get_str("name").ok().map(|s| s.to_string());
        }
    }

    let mut cur = details_coll
        .find(doc! { "invoice_id": &inv.id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut rows: Vec<serde_json::Value> = vec![];

    while let Some(d) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        let item_id = d.get_str("item_id").unwrap_or("").to_string();
        let price = f64_from(&d, "price");
        let quantity = f64_from(&d, "quantity");
        let total = f64_from(&d, "total");

        let mut item_name = opt_string(&d, "item_name").unwrap_or_else(|| item_id.clone());
        let mut section = opt_string(&d, "section").unwrap_or_else(|| "عام".to_string());

        if item_name == item_id || section == "عام" {
            if let Some(itdoc) = items_coll
                .find_one(doc! { "_id": &item_id }, None)
                .await
                .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
            {
                if item_name == item_id {
                    if let Ok(n) = itdoc.get_str("name") {
                        item_name = n.to_string();
                    }
                }
                if section == "عام" {
                    if let Ok(t) = itdoc.get_str("printer_tag") {
                        if !t.trim().is_empty() {
                            section = t.to_string();
                        }
                    }
                    if section == "عام" {
                        if let Ok(cat_id) = itdoc.get_str("category_id") {
                            if let Some(catdoc) = cats_coll
                                .find_one(doc! { "_id": cat_id }, None)
                                .await
                                .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
                            {
                                if let Ok(cn) = catdoc.get_str("name") {
                                    section = cn.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }

        let note = opt_string(&d, "note");

        rows.push(serde_json::json!({
            "item_id": item_id,
            "name": item_name,
            "section": section,
            "price": price,
            "quantity": quantity,
            "total": total,
            "note": note,
        }));
    }

    let payload = serde_json::json!({
        "invoice_id": &inv.id,
        "table_name": table_name,
        "discount": inv.discount,
        "amount_paid": inv.amount_paid,
        "pay_method": inv.pay_method,
        "operator_name": req.operator_name,
        "rows": rows
    });

    emit_all_compat("server:print", &payload);
    log_app("server:print emitted (pay)");

    Ok(Json(OkMsg { ok: true }))
}

/* ---- print بدون دفع ---- */

#[derive(Deserialize)]
struct PrintReq {
    operator_name: Option<String>,
}

async fn invoice_print(
    State(_ctx): State<Arc<ApiCtx>>,
    Path(id): Path<String>,
    Json(req): Json<PrintReq>,
) -> Result<Json<OkMsg>, Response> {
    log_app(&format!("invoice_print start id={}", id));

    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let invoices: Collection<Document> = database.collection("invoices");
    let details_coll = database.collection::<Document>("invoice_details");
    let items_coll = database.collection::<Document>("items");
    let cats_coll = database.collection::<Document>("categories");
    let tables: Collection<Document> = database.collection("tables");

    let inv_doc = invoices
        .find_one(doc! { "_id": &id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        .ok_or_else(|| Json(ApiError::from("الفاتورة غير موجودة".to_string())).into_response())?;

    let inv = doc_to_inv(inv_doc);

    let mut table_name: Option<String> = None;
    if let Some(tid) = inv.table_id.clone() {
        if let Some(tdoc) = tables
            .find_one(doc! { "id": &tid }, None)
            .await
            .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
        {
            table_name = tdoc.get_str("name").ok().map(|s| s.to_string());
        }
    }

    let mut cur = details_coll
        .find(doc! { "invoice_id": &inv.id }, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut rows: Vec<serde_json::Value> = vec![];

    while let Some(d) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        let item_id = d.get_str("item_id").unwrap_or("").to_string();
        let price = f64_from(&d, "price");
        let quantity = f64_from(&d, "quantity");
        let total = f64_from(&d, "total");

        let mut item_name = opt_string(&d, "item_name").unwrap_or_else(|| item_id.clone());
        let mut section = opt_string(&d, "section").unwrap_or_else(|| "عام".to_string());

        if item_name == item_id || section == "عام" {
            if let Some(itdoc) = items_coll
                .find_one(doc! { "_id": &item_id }, None)
                .await
                .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
            {
                if item_name == item_id {
                    if let Ok(n) = itdoc.get_str("name") {
                        item_name = n.to_string();
                    }
                }
                if section == "عام" {
                    if let Ok(t) = itdoc.get_str("printer_tag") {
                        if !t.trim().is_empty() {
                            section = t.to_string();
                        }
                    }
                    if section == "عام" {
                        if let Ok(cat_id) = itdoc.get_str("category_id") {
                            if let Some(catdoc) = cats_coll
                                .find_one(doc! { "_id": cat_id }, None)
                                .await
                                .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
                            {
                                if let Ok(cn) = catdoc.get_str("name") {
                                    section = cn.to_string();
                                }
                            }
                        }
                    }
                }
            }
        }

        let note = opt_string(&d, "note");

        rows.push(serde_json::json!({
            "item_id": item_id,
            "name": item_name,
            "section": section,
            "price": price,
            "quantity": quantity,
            "total": total,
            "note": note,
        }));
    }

    let payload = serde_json::json!({
        "invoice_id": &inv.id,
        "table_name": table_name,
        "discount": inv.discount,
        "amount_paid": inv.amount_paid,
        "pay_method": inv.pay_method,
        "operator_name": req
            .operator_name
            .unwrap_or_else(|| "iPad".into()),
        "rows": rows
    });

    emit_all_compat("server:print", &payload);
    log_app("server:print emitted (manual)");

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Products (Ledger movements) CRUD ================== */

#[derive(Deserialize)]
struct ProductsCreateReq {
    pub note: Option<String>,
    pub transaction_type: String,
    pub price: f64,
    pub currency: String,
    pub user_id: String,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
struct ProductsUpdateReq {
    pub note: Option<String>,
    pub transaction_type: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub user_id: Option<String>,
    pub created_at: Option<String>,
}

async fn products_list(Query(q): Query<ProductsQuery>) -> Result<Json<Vec<ProductsDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("products");

    let filter = if let Some(uid) = q.user_id {
        doc! { "user_id": uid }
    } else {
        doc! {}
    };

    let mut cur = coll
        .find(filter, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(ProductsDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            note: opt_string(&docu, "note"),
            transaction_type: docu
                .get_str("transaction_type")
                .unwrap_or_default()
                .to_string(),
            price: f64_from(&docu, "price"),
            currency: docu.get_str("currency").unwrap_or("IQD").to_string(),
            user_id: docu.get_str("user_id").unwrap_or_default().to_string(),
            created_at: docu
                .get_str("created_at")
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(now_iso_rfc3339),
        });
    }

    Ok(Json(out))
}

async fn product_add(Json(req): Json<ProductsCreateReq>) -> Result<Json<ProductsDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("products");

    let id = Uuid::new_v4().to_string();
    let created_at = req
        .created_at
        .clone()
        .unwrap_or_else(now_iso_rfc3339);

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
        "transaction_type": &req.transaction_type,
        "price": req.price,
        "currency": &req.currency,
        "user_id": &req.user_id,
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(ProductsDto {
        id,
        note: req.note,
        transaction_type: req.transaction_type,
        price: req.price,
        currency: req.currency,
        user_id: req.user_id,
        created_at,
    }))
}

async fn product_update(
    Path(id): Path<String>,
    Json(req): Json<ProductsUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("products");

    let mut set_doc = Document::new();
    if let Some(v) = req.note {
        set_doc.insert("note", v);
    }
    if let Some(v) = req.transaction_type {
        set_doc.insert("transaction_type", v);
    }
    if let Some(v) = req.price {
        set_doc.insert("price", v);
    }
    if let Some(v) = req.currency {
        set_doc.insert("currency", v);
    }
    if let Some(v) = req.user_id {
        set_doc.insert("user_id", v);
    }
    if let Some(v) = req.created_at {
        set_doc.insert("created_at", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn product_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("products");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== BoxData CRUD ================== */

#[derive(Deserialize)]
struct BoxCreateReq {
    pub note: Option<String>,
    pub price: f64,
    pub type_field: String,         // "in" / "out" نفس الواجهة
    pub created_at: Option<String>, // ISO string أو null
    pub currency: String,           // "IQD" أو غيره
}

#[derive(Deserialize)]
struct BoxUpdateReq {
    pub note: Option<String>,
    pub price: Option<f64>,
    pub type_field: Option<String>,         // "in" / "out"
    pub created_at: Option<String>,
    pub currency: Option<String>,
}

async fn box_list() -> Result<Json<Vec<BoxDataDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("boxdata");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(BoxDataDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            note: opt_string(&docu, "note"),
            price: f64_from(&docu, "price"),
            // نقرأ الحقل نفس ما Tauri يكتبه: type_field
            type_field: docu
                .get_str("type_field")
                .unwrap_or("in")
                .to_string(),
            created_at: docu
                .get_str("created_at")
                .ok()
                .map(|s| s.to_string())
                .unwrap_or_else(now_iso_rfc3339),
            currency: docu.get_str("currency").unwrap_or("IQD").to_string(),
        });
    }

    Ok(Json(out))
}

async fn box_add(Json(req): Json<BoxCreateReq>) -> Result<Json<BoxDataDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("boxdata");

    let id = Uuid::new_v4().to_string();
    let created_at = req
        .created_at
        .clone()
        .unwrap_or_else(now_iso_rfc3339);

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
        "price": req.price,
        "type_field": &req.type_field, // 👈 نفس Tauri
        "created_at": &created_at,
        "currency": &req.currency,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(BoxDataDto {
        id,
        note: req.note,
        price: req.price,
        type_field: req.type_field,
        created_at,
        currency: req.currency,
    }))
}

async fn box_update(
    Path(id): Path<String>,
    Json(req): Json<BoxUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("boxdata");

    let mut set_doc = Document::new();
    if let Some(v) = req.note {
        set_doc.insert("note", v);
    }
    if let Some(v) = req.price {
        set_doc.insert("price", v);
    }
    if let Some(v) = req.type_field {
        // نخزن في Mongo بنفس حقل Tauri
        set_doc.insert("type_field", v);
    }
    if let Some(v) = req.created_at {
        set_doc.insert("created_at", v);
    }
    if let Some(v) = req.currency {
        set_doc.insert("currency", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn box_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("boxdata");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Profits CRUD ================== */

#[derive(Deserialize)]
struct ProfitCreateReq {
    pub note: Option<String>,
    pub amount: f64,
    pub profit_type: String,
    pub date: String,
}

#[derive(Deserialize)]
struct ProfitUpdateReq {
    pub note: Option<String>,
    pub amount: Option<f64>,
    pub profit_type: Option<String>,
    pub date: Option<String>,
}

async fn profits_list() -> Result<Json<Vec<ProfitDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("profits");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(ProfitDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            note: opt_string(&docu, "note"),
            amount: f64_from(&docu, "amount"),
            profit_type: docu
                .get_str("profit_type")
                .unwrap_or_default()
                .to_string(),
            date: docu.get_str("date").unwrap_or_default().to_string(),
        });
    }

    Ok(Json(out))
}

async fn profit_add(Json(req): Json<ProfitCreateReq>) -> Result<Json<ProfitDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("profits");

    let id = Uuid::new_v4().to_string();

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
        "amount": req.amount,
        "profit_type": &req.profit_type,
        "date": &req.date,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(ProfitDto {
        id,
        note: req.note,
        amount: req.amount,
        profit_type: req.profit_type,
        date: req.date,
    }))
}

async fn profit_update(
    Path(id): Path<String>,
    Json(req): Json<ProfitUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("profits");

    let mut set_doc = Document::new();
    if let Some(v) = req.note {
        set_doc.insert("note", v);
    }
    if let Some(v) = req.amount {
        set_doc.insert("amount", v);
    }
    if let Some(v) = req.profit_type {
        set_doc.insert("profit_type", v);
    }
    if let Some(v) = req.date {
        set_doc.insert("date", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn profit_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("profits");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Suppliers CRUD ================== */

#[derive(Deserialize)]
struct SupplierCreateReq {
    pub name: String,
    pub phone: Option<String>,
    pub note: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
struct SupplierUpdateReq {
    pub name: Option<String>,
    pub phone: Option<String>,
    pub note: Option<String>,
    pub created_at: Option<String>,
}

async fn suppliers_list() -> Result<Json<Vec<SupplierDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("suppliers");

    let mut cur = coll
        .find(doc! {}, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(SupplierDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            name: docu.get_str("name").unwrap_or_default().to_string(),
            phone: opt_string(&docu, "phone"),
            note: opt_string(&docu, "note"),
            created_at: opt_string(&docu, "created_at"),
        });
    }

    Ok(Json(out))
}

async fn supplier_add(Json(req): Json<SupplierCreateReq>) -> Result<Json<SupplierDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("suppliers");

    let id = Uuid::new_v4().to_string();
    let created_at = req
        .created_at
        .clone()
        .unwrap_or_else(now_iso_rfc3339);

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "name": &req.name,
        "phone": req.phone.clone().map(Bson::String).unwrap_or(Bson::Null),
        "note": req.note.clone().map(Bson::String).unwrap_or(Bson::Null),
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(SupplierDto {
        id,
        name: req.name,
        phone: req.phone,
        note: req.note,
        created_at: Some(created_at),
    }))
}

async fn supplier_update(
    Path(id): Path<String>,
    Json(req): Json<SupplierUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("suppliers");

    let mut set_doc = Document::new();
    if let Some(v) = req.name {
        set_doc.insert("name", v);
    }
    if let Some(v) = req.phone {
        set_doc.insert("phone", v);
    }
    if let Some(v) = req.note {
        set_doc.insert("note", v);
    }
    if let Some(v) = req.created_at {
        set_doc.insert("created_at", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn supplier_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("suppliers");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== SupplierInvoice CRUD ================== */

#[derive(Deserialize)]
struct SupplierInvoiceCreateReq {
    pub supplier_id: String,
    pub invoice_id: Option<String>,
    pub amount: f64,
    pub created_at: Option<String>,
}

#[derive(Deserialize)]
struct SupplierInvoiceUpdateReq {
    pub supplier_id: Option<String>,
    pub invoice_id: Option<String>,
    pub amount: Option<f64>,
    pub created_at: Option<String>,
}

async fn supplier_invoices_list(
    Query(q): Query<SupplierInvoicesQuery>,
) -> Result<Json<Vec<SupplierInvoiceDto>>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("supplier_invoices");

    let filter = if let Some(sid) = q.supplier_id {
        doc! { "supplier_id": sid }
    } else {
        doc! {}
    };

    let mut cur = coll
        .find(filter, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    let mut out = vec![];
    while let Some(docu) = cur
        .try_next()
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?
    {
        out.push(SupplierInvoiceDto {
            id: docu
                .get_str("id")
                .or_else(|_| docu.get_str("_id"))
                .unwrap_or_default()
                .to_string(),
            supplier_id: docu
                .get_str("supplier_id")
                .unwrap_or_default()
                .to_string(),
            invoice_id: opt_string(&docu, "invoice_id"),
            amount: f64_from(&docu, "amount"),
            created_at: opt_string(&docu, "created_at"),
        });
    }

    Ok(Json(out))
}

async fn supplier_invoice_add(
    Json(req): Json<SupplierInvoiceCreateReq>,
) -> Result<Json<SupplierInvoiceDto>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("supplier_invoices");

    let id = Uuid::new_v4().to_string();
    let created_at = req
        .created_at
        .clone()
        .unwrap_or_else(now_iso_rfc3339);

    let docu = doc! {
        "_id": &id,
        "id": &id,
        "supplier_id": &req.supplier_id,
        "invoice_id": req.invoice_id.clone().map(Bson::String).unwrap_or(Bson::Null),
        "amount": req.amount,
        "created_at": &created_at,
    };

    coll.insert_one(docu, None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(SupplierInvoiceDto {
        id,
        supplier_id: req.supplier_id,
        invoice_id: req.invoice_id,
        amount: req.amount,
        created_at: Some(created_at),
    }))
}

async fn supplier_invoice_update(
    Path(id): Path<String>,
    Json(req): Json<SupplierInvoiceUpdateReq>,
) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("supplier_invoices");

    let mut set_doc = Document::new();
    if let Some(v) = req.supplier_id {
        set_doc.insert("supplier_id", v);
    }
    if let Some(v) = req.invoice_id {
        set_doc.insert("invoice_id", v);
    }
    if let Some(v) = req.amount {
        set_doc.insert("amount", v);
    }
    if let Some(v) = req.created_at {
        set_doc.insert("created_at", v);
    }

    if !set_doc.is_empty() {
        coll.update_one(
            id_filter(&id),
            doc! { "$set": set_doc },
            None,
        )
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    }

    Ok(Json(OkMsg { ok: true }))
}

async fn supplier_invoice_delete(Path(id): Path<String>) -> Result<Json<OkMsg>, Response> {
    let database = db().map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;
    let coll: Collection<Document> = database.collection("supplier_invoices");

    coll.delete_one(id_filter(&id), None)
        .await
        .map_err(|e| Json(ApiError::from(e.to_string())).into_response())?;

    Ok(Json(OkMsg { ok: true }))
}

/* ================== Runner ================== */

use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub async fn run_http_server() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let api_key = std::env::var("POS_API_KEY").unwrap_or_else(|_| "SUPER_SECRET_API_KEY_123".into());
    let hmac_secret =
        std::env::var("POS_HMAC_SECRET").unwrap_or_else(|_| "dev-secret-xyz".into());

    println!("[boot] POS_API_KEY = {}", api_key);

    let ctx = Arc::new(ApiCtx {
        api_key,
        hmac_secret,
    });

let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(Any);

let public = Router::new()
    .route("/api/health", get(health))
    .route("/api/login", post(login));

let protected = Router::new()
    // admins
    .route("/api/admins", get(admins_list).post(admin_add))
    .route("/api/admins/:id", put(admin_update).delete(admin_delete))

    // users
    .route("/api/users", get(users_list).post(user_add))
    .route("/api/users/:id", put(user_update).delete(user_delete))

    // categories
    .route("/api/categories", get(categories_list).post(category_add))
    .route("/api/categories/:id", put(category_update).delete(category_delete))

    // items
    .route("/api/items", get(items_list).post(item_add))
    .route("/api/items/:id", put(item_update).delete(item_delete))

    // tables
    .route("/api/tables", get(tables_list).post(table_add))
    .route("/api/tables/:id", put(table_update).delete(table_delete))

    // invoices core
    .route("/api/invoices", get(invoices_list))
    .route("/api/invoice/open", post(invoice_open))
    .route("/api/invoice/move", post(invoice_move))
    .route("/api/invoice/:id", get(invoice_get))
    .route("/api/invoice/:id/details", get(invoice_details))
    .route("/api/invoice/:id/add", post(invoice_add_or_inc))
    .route("/api/invoice/:id/dec", post(invoice_decrement_or_remove))
    .route("/api/invoice/:id/pay", post(invoice_pay_and_close))
    .route("/api/invoice/:id/void", post(invoice_close_void))
    .route("/api/invoice/:id/print", post(invoice_print))

    // ledger products (movements)
    .route("/api/products", get(products_list).post(product_add))
    .route("/api/products/:id", put(product_update).delete(product_delete))

    // box
    .route("/api/box", get(box_list).post(box_add))
    .route("/api/box/:id", put(box_update).delete(box_delete))

    // profits
    .route("/api/profits", get(profits_list).post(profit_add))
    .route("/api/profits/:id", put(profit_update).delete(profit_delete))

    // suppliers
    .route("/api/suppliers", get(suppliers_list).post(supplier_add))
    .route("/api/suppliers/:id", put(supplier_update).delete(supplier_delete))

    // supplier invoices
    .route("/api/supplier_invoices", get(supplier_invoices_list).post(supplier_invoice_add))
    .route("/api/supplier_invoices/:id", put(supplier_invoice_update).delete(supplier_invoice_delete))

    // ✅ طبّق auth_mw فقط هنا
    .layer(from_fn_with_state(ctx.clone(), auth_mw));

let app = public
    .merge(protected)
    .with_state(ctx.clone())
    .layer(cors)
    .layer(TraceLayer::new_for_http());


let port: u16 = std::env::var("PORT")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(3000);

let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(target: "http", "[http] listening on http://{addr}");

    axum::serve(listener, app).await?;
    Ok(())
}
