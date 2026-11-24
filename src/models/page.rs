//! Keyset reads for oversized owner collections.
use serde::{Deserialize, de::DeserializeOwned};
use wasm_bindgen::JsValue;
use worker::D1Database;

use crate::{errors::AppResult, infra::db};

// D1 limits an individual row to 2,000,000 bytes and a query response to
// 50 MB. JSON escaping may expand each raw byte by up to six times.
const PAGE_BYTES: u32 = 4_000_000;
const PAGE_ROWS: u32 = 200;

pub(crate) struct PageCursor {
    rowid: String,
    date: String,
}

pub(crate) struct Page<T> {
    pub rows: Vec<T>,
    pub next: Option<PageCursor>,
}

pub(crate) enum PageOrder {
    RowId,
    NewestFirst,
    CreatedFirst,
}

pub(crate) struct PageQuery {
    pub table: &'static str,
    pub filter: &'static str,
    pub text_columns: &'static [&'static str],
    pub order: PageOrder,
    pub related_bytes: Option<&'static str>,
}

#[derive(Deserialize)]
struct PageRow<T> {
    #[serde(flatten)]
    row: T,
    page_rowid: String,
    page_date: String,
    page_has_more: i32,
}

impl PageQuery {
    /// Filter values use SQLite's unnumbered parameters. Table, column and
    /// predicate fragments are constants at call sites.
    pub(crate) async fn fetch<T: DeserializeOwned>(
        &self,
        db: &D1Database,
        filter_params: &[JsValue],
        after: Option<&PageCursor>,
    ) -> AppResult<Page<T>> {
        let sql = self.sql();
        let mut params = filter_params.to_vec();
        params.extend(db::d1_params![
            after.map(|key| key.rowid.as_str()),
            after.map(|key| key.date.as_str()),
            PAGE_ROWS + 1,
            PAGE_BYTES,
        ]);
        let rows = db::query_all::<PageRow<T>>(db.prepare(sql).bind(&params)?).await?;
        let next = rows
            .last()
            .filter(|row| row.page_has_more != 0)
            .map(|row| PageCursor {
                rowid: row.page_rowid.clone(),
                date: row.page_date.clone(),
            });
        Ok(Page {
            rows: rows.into_iter().map(|row| row.row).collect(),
            next,
        })
    }

    pub(crate) async fn fetch_all<T: DeserializeOwned>(
        &self,
        db: &D1Database,
        filter_params: &[JsValue],
    ) -> AppResult<Vec<T>> {
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let page = self.fetch(db, filter_params, after.as_ref()).await?;
            rows.extend(page.rows);
            let Some(next) = page.next else { break };
            after = Some(next);
        }
        Ok(rows)
    }

    fn sql(&self) -> String {
        let (date, after, ordering) = match self.order {
            PageOrder::RowId => ("''", "source.rowid > cursor.rowid", "page_id"),
            PageOrder::NewestFirst => (
                "source.updated_at",
                "source.updated_at < cursor.date OR \
                 (source.updated_at = cursor.date AND source.rowid > cursor.rowid)",
                "page_date DESC, page_id",
            ),
            PageOrder::CreatedFirst => (
                "source.created_at",
                "source.created_at > cursor.date OR \
                 (source.created_at = cursor.date AND source.rowid > cursor.rowid)",
                "page_date, page_id",
            ),
        };
        let size = self
            .text_columns
            .iter()
            .map(|column| format!("COALESCE(length(CAST(source.{column} AS BLOB)),0)"))
            .collect::<Vec<_>>()
            .join("+");
        let related = self.related_bytes.unwrap_or("0");
        let table = self.table;
        let filter = self.filter;
        // Limit the preview by count before ranking it. Fetch only the
        // complete rows that fit the byte budget, plus one cursor flag.
        format!(
            "WITH filtered AS NOT MATERIALIZED (
                 SELECT rowid,* FROM {table} WHERE {filter}
             ), cursor AS (
                 SELECT CAST(? AS INTEGER) AS rowid, ? AS date
             ), preview AS MATERIALIZED (
                 SELECT source.rowid AS page_id, {date} AS page_date, ({size}) + ({related}) AS bytes
                 FROM filtered source CROSS JOIN cursor
                 WHERE cursor.rowid IS NULL OR ({after})
                 ORDER BY {ordering} LIMIT ?
             ), ranked AS (
                 SELECT *, SUM(bytes) OVER (ORDER BY {ordering}) AS total_bytes,
                        ROW_NUMBER() OVER (ORDER BY {ordering}) AS position,
                        COUNT(*) OVER () AS preview_size
                 FROM preview
             )
             SELECT source.*, CAST(page_id AS TEXT) AS page_rowid, page_date,
                    position < preview_size AS page_has_more
             FROM ranked JOIN {table} source ON source.rowid = page_id
             WHERE (total_bytes <= ? AND position < {lookahead}) OR position=1
             ORDER BY {ordering}",
            lookahead = PAGE_ROWS + 1,
        )
    }
}
