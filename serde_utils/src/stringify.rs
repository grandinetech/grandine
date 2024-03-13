// Various standard APIs require numbers to be represented as strings
// (except for error codes and metadata in the Eth Beacon Node API).
// We used `stringify` for that before we had `string_or_native_sequence`.
// `stringify` requires no `#[serde(with = …)]` attributes but is roughly twice as slow.

use serde::Serialize;
use serde_json::{Result, Value};

pub fn stringify(data: impl Serialize) -> Result<Value> {
    let mut value = serde_json::to_value(data)?;
    convert_numbers_to_strings(&mut value);
    Ok(value)
}

fn convert_numbers_to_strings(value: &mut Value) {
    match value {
        Value::Number(number) => *value = Value::String(number.to_string()),
        Value::Object(map) => map.values_mut().for_each(convert_numbers_to_strings),
        Value::Array(vector) => vector.iter_mut().for_each(convert_numbers_to_strings),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[derive(Serialize)]
    struct Inner {
        integer: u64,
        string: &'static str,
    }

    #[derive(Serialize)]
    struct Outer<I> {
        byte: u8,
        integer: u64,
        float: f64,
        inner: Inner,
        array: I,
    }

    #[test]
    fn stringify_converts_numbers_to_strings() -> Result<()> {
        let data = Outer {
            byte: 3,
            integer: 4,
            float: 5.5,
            inner: Inner {
                integer: 12,
                string: "test",
            },
            array: [Inner {
                integer: 1,
                string: "array_test",
            }],
        };

        assert_eq!(
            stringify(data)?,
            json!({
                "byte": "3",
                "integer": "4",
                "float": "5.5",
                "inner": { "integer": "12", "string": "test" },
                "array": [{ "integer": "1", "string": "array_test"}],
            }),
        );

        Ok(())
    }
}
