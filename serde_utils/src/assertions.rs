use core::fmt::Display;

use serde::Serialize;
use serde_json::Value;

pub fn assert_json_contains_no_numbers(input: impl Serialize) {
    fn recurse(path: impl Display, json: &Value) {
        match json {
            Value::Number(number) => {
                panic!("JSON representation contains number {number} at {path}")
            }
            Value::Array(vector) => {
                for (index, element) in vector.iter().enumerate() {
                    recurse(format_args!("{path}[{index}]"), element);
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    recurse(format_args!("{path}.{key}"), value);
                }
            }
            _ => {}
        }
    }

    let json = serde_json::to_value(input).expect("serialization to JSON should succeed");

    recurse("$", &json)
}
