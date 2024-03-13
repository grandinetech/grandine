use hex_fmt::HexFmt;
use serde::Serializer;

pub fn serialize<S: Serializer>(bytes: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.collect_str(&format_args!("0x{}", HexFmt(bytes)))
    } else {
        serializer.serialize_bytes(bytes.as_ref())
    }
}
