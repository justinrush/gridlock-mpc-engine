use anyhow::{ anyhow, bail, Result };
use derive_more::Display;
use serde::{ Deserialize, Serialize };
use std::collections::BTreeMap;
use std::path::{ Path, PathBuf };
use std::{ env, fs };
use thiserror::Error;

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Display)]
pub enum KeyType {
    EdDSA,
    ECDSA,
    TwoFA,
    Sr25519,
    MultiSr25519,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key_type: KeyType,
    pub public_key: String,
    pub node_to_share_indices: Vec<(usize, usize)>,
}

pub struct KeyshareHoldings {
    file_path: PathBuf,
    // Usage of BTreeMap to display sorted keys in json
    keys: BTreeMap<String, KeyInfo>,
}

impl KeyshareHoldings {
    pub fn load<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let s = match fs::read_to_string(&file_path) {
            Ok(s) => s,
            Err(err) => {
                bail!("Need a better way to create file: {}", err);
            }
        };
        let keys = match serde_json::from_str::<BTreeMap<String, KeyInfo>>(&s) {
            Ok(k) => k,
            Err(_err) => BTreeMap::new(),
        };
        Ok(Self {
            file_path: file_path.as_ref().to_owned(),
            keys,
        })
    }

    pub fn update(&mut self, key_id: &str, share_info: KeyInfo) -> Result<()> {
        self.keys.insert(key_id.to_string(), share_info);
        let data = serde_json::to_string_pretty(&self.keys)?;
        fs::write(&self.file_path, data)?;
        Ok(())
    }

    pub fn get_share_index_by_node_index(&self, key_id: &str, node_index: usize) -> Result<usize> {
        let info = self.keys.get(key_id).ok_or_else(|| anyhow!("Key id not found"))?;
        let (_, share_index) = info.node_to_share_indices
            .iter()
            .find(|(n_index, _share_index)| *n_index == node_index)
            .ok_or_else(|| anyhow!("Node index not found for provided key id"))?;
        // let share_index = info.share_indices.get(i).ok_or_else(|| anyhow!("Corresponding share index not found"))?;
        Ok(*share_index)
    }

    pub fn get_public_key(&self, key_id: &str) -> Result<String> {
        let ki = self.keys.get(key_id).ok_or_else(|| anyhow!("Key id not found"))?;
        Ok(ki.public_key.clone())
    }
}

fn local_node_ids() -> Vec<NodeIdentity> {
    let gridlock1 = NodeIdentity::new(
        1,
        "b4b55e6c-ce7d-4604-9316-819538a467cc",
        "UD6BRPUZYPN4VPXSBXNA5WNYUB6NJC4CUB4P5SS73HDN2FCV74WMYJVF"
    );
    let gridlock2 = NodeIdentity::new(
        2,
        "79509c20-dac1-4288-a480-b3db333d367f",
        "UCOJNQ6UFMK6Z7LCETJCUD5EYJ3QHF5LNN32Z3IDEG563KWGUVJQILTH"
    );
    let gridlock3 = NodeIdentity::new(
        3,
        "fde7c87e-ae50-4606-b72e-267c97a849e5",
        "UBXBJAXBHBTHE5O2Q7WE7CXUVCUC5CI72Q42CHAZNOEJEQ6KEK3MGT35"
    );
    let gridlock4 = NodeIdentity::new(
        4,
        "75d45be5-197d-45b4-8df2-ad89e257aa90",
        "UBETH6NUDJOZXUGXEJKYI5ZCWOETHXV66T7OESMOJEJEOM2SHDE7QJN4"
    );
    let gridlock5 = NodeIdentity::new(
        5,
        "008d62d5-c331-432d-937d-94444184bd0d",
        "UA3BQ27VOJSXLFHTFBG5AK752KZFURCAKV6AIRLC2STZO255BTNREBJA"
    );
    let gridlock6 = NodeIdentity::new(
        6,
        "1aa4dfde-10b7-4de0-9a42-aa00c7383db2",
        "UCA45DFH5E27Z453JUH6B5RVGIYLNBI2PA24NFEGPJESPOOSGC67MAP3"
    );

    let (gridlock7, gridlock8) = partner_node_ids();

    vec![gridlock1, gridlock2, gridlock3, gridlock4, gridlock5, gridlock6, gridlock7, gridlock8]
}

fn staging_node_ids() -> Vec<NodeIdentity> {
    let gridlock1 = NodeIdentity::new(
        1,
        "929907ba-6a55-4cc3-825f-748406577734",
        "UACQSJZF2D4QRONVRUCMWTWEDHUEB7OVA2M3V5K3E4ITZ4YDXM3KI3XI"
    );
    let gridlock2 = NodeIdentity::new(
        2,
        "a1c0a0cf-d4b6-4225-8128-69ed7dff49b8",
        "UDDKZJVIXXILSBZFRGRMEJ4P5LGMYOMY4WAVWNXD2S77LIBEYR3LOF6Z"
    );
    let gridlock3 = NodeIdentity::new(
        3,
        "8b642223-b9e7-4cf3-b660-4b8542b77977",
        "UDVIFUVGGZYRZ5I6RMRLGBJPEDBFCVWKDL4HZQLTEUDNYF2MXPDJPAAC"
    );
    let gridlock4 = NodeIdentity::new(
        4,
        "1e22f603-b712-4d03-9a25-90ca72e80e50",
        "UDKRB33PUXXQRF7GHKDY7KUIU7BESVMM4X7ZPVSI7HINUMM6IMSGBEXJ"
    );
    let gridlock5 = NodeIdentity::new(
        5,
        "e7895034-19fe-455a-aca1-9e78b67aa00a",
        "UD5FU5NNAEKOE566P4OUY5BFSYY646W3XVALPHNJMJZDNR32VJKYSJGD"
    );

    let (gridlock7, gridlock8) = partner_node_ids();

    vec![gridlock1, gridlock2, gridlock3, gridlock4, gridlock5, gridlock7, gridlock8]
}

fn production_node_ids() -> Vec<NodeIdentity> {
    let gridlock1 = NodeIdentity::new(
        1,
        "47344dbe-a4d3-4b1a-bfe9-372838b42fee",
        "UCUQXGPWZYVEUW5XTCOMH4Q64O5WU3FGAHD45BPPQMLQNLUMEU2CUKHF"
    );
    let gridlock2 = NodeIdentity::new(
        2,
        "e6d69ebe-d21f-43f3-baba-7ea2cf2b424a",
        "UA2ZQNLCPP2KM4IHXAZLUIJKKCP3MC5Z5CU7XWVF5GHJNN2DVAWKA7UE"
    );
    let gridlock3 = NodeIdentity::new(
        3,
        "2bf6d547-2eda-4885-bead-64e04b5974d4",
        "UDKRJMRERFG5DTHEFNPJOU2327JYP35AYZG7ZWNC44HY3EXCDQXOWGUC"
    );
    let gridlock4 = NodeIdentity::new(
        4,
        "b75b5436-32b8-484e-a545-43a36a5db3ef",
        "UAQPSYW6L43LDX5PPM72FT6TCK7GNKKWUNLBL62OKGRBCLJTZNJYGIA3"
    );
    let gridlock5 = NodeIdentity::new(
        5,
        "d394f2ba-f57b-4762-a5cd-1d5546e67a05",
        "UDN4FCTTJ35USAREUQ37735GNORQ27XTJAMX6CSWKSWP2TY3KHFAFGST"
    );
    let _gridlock6 = NodeIdentity::new(
        6,
        "948d1284-821e-459a-8630-b3cffb9f820d",
        "UCK4H6NXPCWRFPZGEKCRBAEWM7YDE5W7KYGUM3DZ64STUMCKLMFSXZ6Y"
    );

    let (gridlock7, gridlock8) = partner_node_ids();

    vec![gridlock1, gridlock2, gridlock3, gridlock4, gridlock5, gridlock7, gridlock8]
}

fn partner_node_ids() -> (NodeIdentity, NodeIdentity) {
    let gridlock7 = NodeIdentity::new(
        7,
        "5a0d2d12-39c1-44ca-b6c4-188314527b40",
        "UDD2RAAZK7AWGK4QQ32BQ72W4YBS2UWBUBCDSDWTMB4RVYJRSBMBV2AN"
    );
    let gridlock8 = NodeIdentity::new(
        8,
        "009b3169-8c90-464e-b20d-db56ab0f7aba",
        "UAVTQHIJQY7P6VREWNFMGFAC23IIYGTV2NAC3AKMYI4VGY4OLRKSOP7J"
    );
    (gridlock7, gridlock8)
}

#[derive(Clone)]
pub struct NodeIdentity {
    pub node_id: String,
    pub index: usize,
    pub public_key: String,
}

impl NodeIdentity {
    pub fn new(index: usize, node_id: &str, public_key: &str) -> Self {
        Self {
            index,
            node_id: String::from(node_id),
            public_key: String::from(public_key),
        }
    }
}

pub struct AllNodes {
    pub nodes: Vec<NodeIdentity>,
}

impl AllNodes {
    pub fn new(nodes: Vec<NodeIdentity>) -> Self {
        Self { nodes }
    }
    pub fn get_node_by_index(&self, index: usize) -> Result<NodeIdentity> {
        let n = self.nodes
            .iter()
            .find(|n| n.index == index)
            .ok_or(anyhow!("No node found with the index {}", index))?;
        Ok(n.clone())
    }
    pub fn get_all_public_keys(&self) -> Vec<String> {
        self.nodes
            .iter()
            .map(|n| n.public_key.to_owned())
            .collect()
    }
}

pub struct Config {
    pub nodes: AllNodes,
    pub address: String,
    pub keys: KeyshareHoldings,
}

impl Config {
    pub fn new_local() -> Result<Config, ParseConfigError> {
        let keys_file = env
            ::var("NODE_KEYS_FILE")
            .unwrap_or_else(|_| "data/local-keys.json".to_string());
        let nats_addr = env
            ::var("NATS_ADDRESS")
            .unwrap_or_else(|_| "nats://localhost:4222".to_string());
        Self::new(&keys_file, &nats_addr, local_node_ids())
    }

    pub fn new_staging() -> Result<Config, ParseConfigError> {
        Self::new(
            "data/staging-keys.json",
            "nats://stagingnats.gridlock.network:4222",
            staging_node_ids()
        )
    }

    fn new(
        keys_file: &str,
        nats_addr: &str,
        node_vec: Vec<NodeIdentity>
    ) -> Result<Config, ParseConfigError> {
        let keys_file = if Path::new(keys_file).is_absolute() {
            Path::new(keys_file).to_owned()
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(keys_file)
        };
        let nodes = AllNodes::new(node_vec);
        let keys = KeyshareHoldings::load(&keys_file).map_err(|err| {
            ParseConfigError::InvalidKeysFile {
                err: format!("{}; tried path: {}", err, keys_file.to_str().expect("Valid path")),
            }
        })?;

        Ok(Self {
            address: nats_addr.to_string(),
            nodes,
            keys,
        })
    }
}

#[derive(Error, Debug)]
pub enum ParseConfigError {
    #[error(
        "Invalid network (expected `local`, `staging` or `prod`, got {found:?})"
    )] InvalidString {
        found: String,
    },
    #[error("Could not find keys file : {err:?})")] InvalidKeysFile {
        err: String,
    },
    #[error(transparent)] Other(#[from] anyhow::Error),
}
