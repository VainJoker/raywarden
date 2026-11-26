//! Byte- and row-bounded JSON parameters for D1 batches.
pub(super) const JSON_BATCH_BYTES: usize = 1_900_000;

pub(super) enum BatchPush {
    Queued(Option<String>),
    Oversized,
}

pub(super) struct JsonBatch {
    json: String,
    rows: usize,
    maximum_rows: usize,
}

impl JsonBatch {
    pub(super) fn new(maximum_rows: usize) -> Self {
        Self {
            json: String::from("["),
            rows: 0,
            maximum_rows: maximum_rows.max(1),
        }
    }

    pub(super) fn push(&mut self, row: &str) -> BatchPush {
        // Reserve the opening and closing brackets for a single-element array.
        if row.len().saturating_add(2) > JSON_BATCH_BYTES {
            return BatchPush::Oversized;
        }
        // Reserve the closing bracket and one separator for the incoming row.
        let completed = if self.rows >= self.maximum_rows
            || self.json.len() + row.len() + 2 > JSON_BATCH_BYTES
        {
            self.take()
        } else {
            None
        };
        self.json.push_str(row);
        self.json.push(',');
        self.rows += 1;
        BatchPush::Queued(completed)
    }

    pub(super) fn take(&mut self) -> Option<String> {
        if self.rows == 0 {
            return None;
        }
        self.rows = 0;
        self.json.pop();
        self.json.push(']');
        Some(std::mem::replace(&mut self.json, String::from("[")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_groups_respect_row_and_byte_limits() {
        let mut group = JsonBatch::new(200);
        for _ in 0..200 {
            assert!(matches!(group.push("0"), BatchPush::Queued(None)));
        }
        let BatchPush::Queued(Some(group_json)) = group.push("1") else {
            panic!("expected full row group");
        };
        let group_rows: Vec<i32> = serde_json::from_str(&group_json).expect("valid snapshot array");
        assert_eq!(group_rows, vec![0; 200]);
        assert_eq!(group.take().as_deref(), Some("[1]"));

        let row = format!("\"{}\"", "x".repeat(JSON_BATCH_BYTES - 7));
        assert!(matches!(group.push(&row), BatchPush::Queued(None)));
        assert!(matches!(group.push("0"), BatchPush::Queued(None)));
        assert!(matches!(group.push("1"), BatchPush::Queued(Some(_))));
        assert_eq!(group.take().as_deref(), Some("[1]"));

        let exact = "x".repeat(JSON_BATCH_BYTES - 2);
        assert!(matches!(group.push("0"), BatchPush::Queued(None)));
        assert_eq!(
            match group.push(&exact) {
                BatchPush::Queued(flushed) => flushed,
                BatchPush::Oversized => panic!("exact row fits single-element array"),
            }
            .as_deref(),
            Some("[0]")
        );
        assert_eq!(group.take().map(|s| s.len()), Some(JSON_BATCH_BYTES));

        let too_large = "x".repeat(JSON_BATCH_BYTES - 1);
        assert!(matches!(group.push(&too_large), BatchPush::Oversized));
        assert!(group.take().is_none());
    }
}
