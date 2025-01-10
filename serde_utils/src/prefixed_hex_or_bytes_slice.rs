use serde::Serializer;

pub fn serialize<S: Serializer>(bytes: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(const_hex::encode_prefixed(bytes).as_str())
    } else {
        serializer.serialize_bytes(bytes.as_ref())
    }
}
