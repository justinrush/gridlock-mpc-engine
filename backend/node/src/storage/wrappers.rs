use curv::arithmetic::Converter;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::{
    ShamirSecretSharing,
    VerifiableSS,
};
use curv::elliptic::curves::{ Curve, Ed25519, Point, Scalar, Secp256k1 };
use curv::BigInt;
use derive_more::{ Deref, DerefMut, From, Into };
use itertools::Itertools;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SharedKeys as EcSharedKeys;
use multi_party_eddsa::protocols::thresholdsig::SharedKeys;
use schnorrkel::{ ExpansionMode, MiniSecretKey, SecretKey };
use serde::de::{ DeserializeOwned, Error, MapAccess, SeqAccess, Visitor };
use serde::ser::SerializeStruct;
use serde::{ Deserialize, Deserializer, Serialize, Serializer };
use std::fmt;
use zk_paillier::zkproofs::DLogStatement;

#[derive(Deref, DerefMut, From, Into, Debug, Clone)]
pub struct WPoint<C: Curve>(Point<C>);

impl Serialize for WPoint<Secp256k1> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where S: Serializer
    {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.0.x_coord().unwrap().to_hex())?;
        state.serialize_field("y", &self.0.y_coord().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WPoint<Secp256k1> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct Secp256k1PointVisitor;

        impl<'de> Visitor<'de> for Secp256k1PointVisitor {
            type Value = Point<Secp256k1>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Secp256k1Point")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Point<Secp256k1>, V::Error>
                where V: SeqAccess<'de>
            {
                let x = seq
                    .next_element()?
                    .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;
                let y = seq
                    .next_element()?
                    .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;

                let bx = BigInt::from_hex(x).map_err(V::Error::custom)?;
                let by = BigInt::from_hex(y).map_err(V::Error::custom)?;

                Point::<Secp256k1>::from_coords(&bx, &by).map_err(V::Error::custom)
            }

            fn visit_map<E: MapAccess<'de>>(
                self,
                mut map: E
            ) -> Result<Point<Secp256k1>, E::Error> {
                let mut x = String::new();
                let mut y = String::new();

                while let Some(ref key) = map.next_key::<String>()? {
                    let v = map.next_value::<String>()?;
                    if key == "x" {
                        x = v;
                    } else if key == "y" {
                        y = v;
                    } else {
                        return Err(E::Error::unknown_field(key, &["x", "y"]));
                    }
                }

                let bx = BigInt::from_hex(&x).map_err(E::Error::custom)?;
                let by = BigInt::from_hex(&y).map_err(E::Error::custom)?;

                Point::<Secp256k1>::from_coords(&bx, &by).map_err(E::Error::custom)
            }
        }

        let fields = &["x", "y"];
        deserializer.deserialize_struct("Secp256k1Point", fields, Secp256k1PointVisitor).map(WPoint)
    }
}

impl Serialize for WPoint<Ed25519> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let bytes = self.0.to_bytes(false).to_vec();
        let bytes_as_bn = BigInt::from_bytes(&bytes[..]);
        let padded_bytes_hex = format!("{:0>64}", bytes_as_bn.to_hex());
        let mut state = serializer.serialize_struct("ed25519CurvePoint", 1)?;
        state.serialize_field("bytes_str", &padded_bytes_hex)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for WPoint<Ed25519> {
    fn deserialize<D>(deserializer: D) -> Result<WPoint<Ed25519>, D::Error>
        where D: Deserializer<'de>
    {
        struct Ed25519PointVisitor;

        impl<'de> Visitor<'de> for Ed25519PointVisitor {
            type Value = Point<Ed25519>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Ed25519Point")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Point<Ed25519>, V::Error>
                where V: SeqAccess<'de>
            {
                let bytes_str = seq
                    .next_element()?
                    .ok_or_else(|| V::Error::invalid_length(0, &"a single element"))?;
                let bytes_bn = BigInt::from_hex(bytes_str).map_err(V::Error::custom)?;
                let bytes = BigInt::to_bytes(&bytes_bn);
                Point::<Ed25519>
                    ::from_bytes(&bytes[..])
                    .map_err(|_| V::Error::custom("failed to parse ed25519 point"))
            }

            fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Point<Ed25519>, E::Error> {
                let mut bytes_str: String = "".to_string();

                while let Some(key) = map.next_key::<&'de str>()? {
                    let v = map.next_value::<&'de str>()?;
                    match key {
                        "bytes_str" => {
                            bytes_str = String::from(v);
                        }
                        _ => {
                            return Err(E::Error::unknown_field(key, &["bytes_str"]));
                        }
                    }
                }

                let bytes_bn = BigInt::from_hex(&bytes_str).map_err(E::Error::custom)?;
                let bytes = BigInt::to_bytes(&bytes_bn);

                Point::<Ed25519>
                    ::from_bytes(&bytes[..])
                    .map_err(|_| E::Error::custom("invalid ed25519 point"))
            }
        }

        let fields = &["bytes_str"];
        deserializer.deserialize_struct("Ed25519Point", fields, Ed25519PointVisitor).map(WPoint)
    }
}

#[derive(Deref, DerefMut, From, Into, Debug, Clone)]
pub struct WScalar<C: Curve>(Scalar<C>);

impl Serialize for WScalar<Secp256k1> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(&self.0.to_bigint().to_hex())
    }
}

impl<'de> Deserialize<'de> for WScalar<Secp256k1> {
    fn deserialize<D>(deserializer: D) -> Result<WScalar<Secp256k1>, D::Error>
        where D: Deserializer<'de>
    {
        struct Secp256k1ScalarVisitor;

        impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
            type Value = Scalar<Secp256k1>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Secp256k1Scalar")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<Scalar<Secp256k1>, E> {
                let v = BigInt::from_hex(s).map_err(E::custom)?;
                Ok(Scalar::<Secp256k1>::from_bigint(&v))
            }
        }

        deserializer.deserialize_str(Secp256k1ScalarVisitor).map(WScalar)
    }
}

impl Serialize for WScalar<Ed25519> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(&self.0.to_bigint().to_hex())
    }
}

impl<'de> Deserialize<'de> for WScalar<Ed25519> {
    fn deserialize<D>(deserializer: D) -> Result<WScalar<Ed25519>, D::Error>
        where D: Deserializer<'de>
    {
        struct Ed25519ScalarVisitor;

        impl<'de> Visitor<'de> for Ed25519ScalarVisitor {
            type Value = Scalar<Ed25519>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ed25519")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<Scalar<Ed25519>, E> {
                let v = BigInt::from_hex(s).map_err(E::custom)?;
                Ok(Scalar::<Ed25519>::from_bigint(&v))
            }
        }

        deserializer.deserialize_str(Ed25519ScalarVisitor).map(WScalar)
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct WShamirSecretSharing {
    pub threshold: u16, //t
    pub share_count: u16, //n
}

impl From<ShamirSecretSharing> for WShamirSecretSharing {
    fn from(value: ShamirSecretSharing) -> Self {
        Self {
            threshold: value.threshold,
            share_count: value.share_count,
        }
    }
}

impl From<WShamirSecretSharing> for ShamirSecretSharing {
    fn from(value: WShamirSecretSharing) -> Self {
        Self {
            threshold: value.threshold,
            share_count: value.share_count,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct WVerifiableSS<E> where E: Curve, WPoint<E>: Serialize + DeserializeOwned {
    pub parameters: WShamirSecretSharing,
    pub commitments: Vec<WPoint<E>>,
}

impl<E> From<VerifiableSS<E>>
    for WVerifiableSS<E>
    where E: Curve, WPoint<E>: Serialize + DeserializeOwned
{
    fn from(value: VerifiableSS<E>) -> Self {
        Self {
            parameters: value.parameters.into(),
            commitments: value.commitments.into_iter().map_into().collect(),
        }
    }
}

impl<E> From<WVerifiableSS<E>>
    for VerifiableSS<E>
    where E: Curve, WPoint<E>: Serialize + DeserializeOwned
{
    fn from(value: WVerifiableSS<E>) -> Self {
        Self {
            parameters: value.parameters.into(),
            commitments: value.commitments.into_iter().map_into().collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WDLogStatement {
    pub N: WBigInt,
    pub g: WBigInt,
    pub ni: WBigInt,
}

impl From<DLogStatement> for WDLogStatement {
    fn from(value: DLogStatement) -> Self {
        WDLogStatement {
            N: value.N.into(),
            g: value.g.into(),
            ni: value.ni.into(),
        }
    }
}

impl From<WDLogStatement> for DLogStatement {
    fn from(value: WDLogStatement) -> Self {
        DLogStatement {
            N: value.N.into(),
            g: value.g.into(),
            ni: value.ni.into(),
        }
    }
}

#[derive(Debug, From, Into, Deref, Clone)]
pub struct WBigInt(BigInt);

const HEX_RADIX: u8 = 16;

impl Serialize for WBigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_str(&self.0.to_str_radix(HEX_RADIX))
    }
}

impl<'de> Deserialize<'de> for WBigInt {
    fn deserialize<D>(deserializer: D) -> Result<WBigInt, D::Error> where D: Deserializer<'de> {
        struct BigIntVisitor;

        impl<'de> Visitor<'de> for BigIntVisitor {
            type Value = WBigInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("BigInt")
            }

            fn visit_str<E: Error>(self, s: &str) -> Result<WBigInt, E> {
                Ok(WBigInt(BigInt::from_str_radix(s, HEX_RADIX).expect("Failed in serde")))
            }
        }
        deserializer.deserialize_str(BigIntVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WEdSharedKeys {
    pub y: WPoint<Ed25519>,
    pub x_i: WScalar<Ed25519>,
    pub prefix: WScalar<Ed25519>,
}

impl From<SharedKeys> for WEdSharedKeys {
    fn from(value: SharedKeys) -> Self {
        WEdSharedKeys {
            y: value.y.into(),
            x_i: value.x_i.into(),
            prefix: value.prefix.into(),
        }
    }
}

impl From<WEdSharedKeys> for SharedKeys {
    fn from(value: WEdSharedKeys) -> Self {
        SharedKeys {
            y: value.y.into(),
            x_i: value.x_i.into(),
            prefix: value.prefix.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WEdKeys {
    pub u_i: WScalar<Ed25519>, // private_key
    pub y_i: WPoint<Ed25519>, // public_key
    pub prefix: WScalar<Ed25519>,
    pub party_index: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WEcSharedKeys {
    pub y: WPoint<Secp256k1>,
    pub x_i: WScalar<Secp256k1>,
}

impl From<EcSharedKeys> for WEcSharedKeys {
    fn from(value: EcSharedKeys) -> Self {
        WEcSharedKeys {
            y: value.y.into(),
            x_i: value.x_i.into(),
        }
    }
}

impl From<WEcSharedKeys> for EcSharedKeys {
    fn from(value: WEcSharedKeys) -> Self {
        EcSharedKeys {
            y: value.y.into(),
            x_i: value.x_i.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct SchnorrkelSecretKey(String);

impl SchnorrkelSecretKey {
    /// Generate secret key from Scalar::<Ed25519>::random() because it will create
    /// 3 first bits zeroed and it will work fine with secret sharing.
    /// It's a bit awkward behaviour of curv-kzen library.
    pub fn generate() -> Self {
        let scalar = Scalar::<Ed25519>::random();
        let hex_scalar = hex::encode(scalar.to_bytes().to_vec());
        SchnorrkelSecretKey(hex_scalar)
    }
}

impl From<Scalar<Ed25519>> for SchnorrkelSecretKey {
    fn from(value: Scalar<Ed25519>) -> Self {
        let hex = hex::encode(value.to_bytes().to_vec());
        SchnorrkelSecretKey(hex)
    }
}

impl From<SchnorrkelSecretKey> for Scalar<Ed25519> {
    fn from(value: SchnorrkelSecretKey) -> Self {
        let bytes = hex::decode(value.0).expect("hex decoded SchnorrkelSecretKey");
        Scalar::<Ed25519>::from_bytes(&bytes).expect("scalar constructed from bytes")
    }
}

impl From<MiniSecretKey> for SchnorrkelSecretKey {
    fn from(value: MiniSecretKey) -> Self {
        Self(hex::encode(value.to_bytes()))
    }
}

impl From<SchnorrkelSecretKey> for MiniSecretKey {
    fn from(value: SchnorrkelSecretKey) -> Self {
        let bytes = hex::decode(value.0).expect("hex decoded SchnorrkelSecretKey");
        MiniSecretKey::from_bytes(&bytes).expect("MiniSecretKey created from bytes)")
    }
}

impl From<SchnorrkelSecretKey> for SecretKey {
    fn from(value: SchnorrkelSecretKey) -> Self {
        let mini_key: MiniSecretKey = value.into();
        mini_key.expand(ExpansionMode::Ed25519)
    }
}

#[test]
fn can_convert_between_SchnorrkelSecretKey_and_ed25519_scalar() {
    let key = SchnorrkelSecretKey(
        "c7a6092f36147a916e6e4de83542f7e49dee2a005ca3eea7307457d5db059353".to_string()
    );
    let scalar: Scalar<Ed25519> = key.clone().into();
    dbg!(&scalar);
    dbg!(&scalar.to_bytes().len());
    dbg!(&scalar.to_bigint());
    let key2: SchnorrkelSecretKey = scalar.into();
    assert_eq!(key, key2);
}
