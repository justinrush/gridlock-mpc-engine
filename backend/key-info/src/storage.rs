use crate::UpdateCommand;
use anyhow::Result;
use chrono::{ DateTime, Utc };
use futures::stream::{ StreamExt, TryStreamExt };
use log::info;
use mongodb::bson::doc;
use mongodb::{ Client, Database };
use serde::{ Deserialize, Serialize };
use shared::key_info::NodeId;

#[derive(Serialize, Deserialize)]
pub struct NodeUpdateData {
    pub update_cmd: UpdateCommand,
    pub message_type: String,
    pub update_time: Option<DateTime<Utc>>,
    pub node_id: NodeId,
}

impl NodeUpdateData {
    pub fn new(update_command: UpdateCommand, node_id: NodeId) -> Self {
        let message_type = format!("{}", &update_command);
        NodeUpdateData {
            update_cmd: update_command,
            message_type,
            update_time: None,
            node_id,
        }
    }
}

pub async fn save(data: NodeUpdateData) -> Result<()> {
    let db = get_db().await?;
    let collection = db.collection::<NodeUpdateData>("keyInfo");
    collection.insert_one(data, None).await?;
    Ok(())
}

pub async fn get_updates_for(node_id: &NodeId) -> Result<Vec<NodeUpdateData>> {
    let db = get_db().await?;
    let collection = db.collection::<NodeUpdateData>("keyInfo");
    let cursor = collection.find(
        doc! { "node_id": node_id.to_string(), "update_time": Option::<DateTime<Utc>>::None },
        None
    ).await?;
    Ok(cursor.try_collect().await?)
}

pub async fn mark_updated(node_id: &NodeId) -> Result<()> {
    let db = get_db().await?;
    let collection = db.collection::<NodeUpdateData>("keyInfo");
    let result = collection.update_many(
        doc! { "node_id": node_id.to_string() },
        doc! { "update_time": Some(chrono::Utc::now()) },
        None
    ).await?;
    info!(
        "KeyInfo updated - node_id: {}, document updated count: {}",
        node_id,
        result.modified_count
    );
    Ok(())
}

async fn get_db() -> Result<Database> {
    // TODO#q: use different environment for staging and production. Should we create new database?
    let client = Client::with_uri_str("mongodb://user:password@mongodb:27017").await?;
    let db = client.database("testdb");
    Ok(db)
}
