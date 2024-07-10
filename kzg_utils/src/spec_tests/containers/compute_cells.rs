#![expect(clippy::string_slice)]

use crate::eip_7594::try_convert_to_cell;

use serde::Deserialize;
use types::{fulu::primitives::Cell, preset::Preset};

#[derive(Deserialize)]
pub struct Input {
    pub blob: String,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<Vec<String>>,
}

impl Test {
    pub fn get_output<P: Preset>(&self) -> Option<Vec<Cell<P>>> {
        self.output.as_ref().map(|cells_str| {
            cells_str
                .iter()
                .map(|cell| {
                    let bytes = hex::decode(&cell[2..]).expect("should decode cell bytes");

                    try_convert_to_cell::<P>(bytes)
                        .expect("test output cell bytes should fit into BYTES_PER_CELL bytes")
                })
                .collect::<Vec<_>>()
        })
    }
}
