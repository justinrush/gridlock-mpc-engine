use crate::storage::fs::FileSystem;
use anyhow::Result;
use nkeys::KeyPair;
use serde::{ Deserialize, Serialize };
use sodiumoxide::crypto::box_::gen_keypair;
use uuid::Uuid;
use rand::seq::SliceRandom;

const NODE_NAMES: &[&str] = &[
    "Cletus",
    "Vern",
    "Bertha",
    "Earl",
    "Myrtle",
    "Otis",
    "Doris",
    "Clovis",
    "Gus",
    "Mabel",
    "Clyde",
    "Darla",
    "Buford",
    "Norma",
    "Wilbur",
    "Blanche",
    "Homer",
    "Gladys",
    "Chester",
    "Agnes",
    "Elmer",
    "Hazel",
    "Lloyd",
    "Velma",
    "Rufus",
    "Edna",
    "Virgil",
    "Gertrude",
    "Lem",
    "Nellie",
    "Alvin",
    "Thelma",
    "Delbert",
    "Pearl",
    "Floyd",
    "Hattie",
    "Roscoe",
    "Opal",
    "Junior",
    "Fern",
    "Eunice",
    "Burl",
    "Beulah",
    "Marvin",
    "Dewey",
    "Phyllis",
    "Waldo",
    "Eula",
    "Maynard",
    "Enos",
];

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeIdentity {
    pub node_id: Uuid,
    pub networking_public_key: String,
    pub networking_private_key: String,
    pub e2e_public_key: String,
    pub e2e_private_key: String,
    pub name: String,
}

impl NodeIdentity {
    pub fn new() -> Self {
        let node_id = Uuid::new_v4();
        let node_kp = KeyPair::new_user();
        let networking_public_key = node_kp.public_key();
        let networking_private_key = node_kp.seed().unwrap();
        let (e2e_public_key, e2e_private_key) = gen_keypair();
        let name = NODE_NAMES.choose(&mut rand::thread_rng()).unwrap_or(&"Node").to_string();
        Self {
            node_id,
            networking_public_key,
            networking_private_key,
            e2e_public_key: base64::encode(e2e_public_key.as_ref()),
            e2e_private_key: base64::encode(e2e_private_key.as_ref()),
            name,
        }
    }

    pub fn from(
        node_id: Uuid,
        networking_public_key: String,
        networking_private_key: String,
        e2e_public_key: String,
        e2e_private_key: String,
        name: String
    ) -> Self {
        Self {
            node_id,
            networking_public_key,
            networking_private_key,
            e2e_public_key,
            e2e_private_key,
            name,
        }
    }

    pub fn load() -> Result<Self> {
        let data = FileSystem::read_node_identity()?;
        let node = serde_json::from_str::<Self>(&data)?;
        Ok(node)
    }

    pub fn save(&self) -> Result<()> {
        let contents = serde_json::to_string(&self)?;
        FileSystem::save_node_identity(&contents)?;
        Ok(())
    }
}
