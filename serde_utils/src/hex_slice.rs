use serde::Serializer;

pub fn serialize<S: Serializer>(bytes: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(const_hex::encode(bytes).as_str())
}
