use serde::{
    Deserialize,
    Serialize,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttachmentDB {
    pub id:              String,
    pub cipher_id:       String,
    pub file_name:       String,
    pub file_size:       i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub akey:            Option<String>,
    pub created_at:      String,
    pub updated_at:      String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentResponse {
    pub id:        String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url:       Option<String>,
    pub file_name: String,
    pub size:      String,
    pub size_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key:       Option<String>,
    pub object:    String,
}

impl AttachmentDB {
    pub fn r2_key(&self) -> String {
        format!("{}/{}", self.cipher_id, self.id)
    }

    pub fn to_response(&self, url: Option<String>) -> AttachmentResponse {
        AttachmentResponse {
            id: self.id.clone(),
            url,
            file_name: self.file_name.clone(),
            size: self.file_size.to_string(),
            size_name: display_size(self.file_size),
            key: self.akey.clone(),
            object: "attachment".to_string(),
        }
    }
}

fn display_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];

    if bytes < 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}
