#![expect(clippy::string_slice)]

use crate::eip_7594::try_convert_to_cell;

use serde::Deserialize;
use types::{deneb::primitives::KzgProof, fulu::primitives::Cell, preset::Preset};

#[derive(Deserialize)]
pub struct Input {
    pub cell_indices: Vec<u64>,
    pub cells: Vec<String>,
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Option<(Vec<String>, Vec<String>)>,
}

impl Test {
    pub fn get_output<P: Preset>(&self) -> Option<(Vec<Cell<P>>, Vec<KzgProof>)> {
        self.output.as_ref().map(|(cells_str, proofs_str)| {
            let cells = cells_str
                .iter()
                .map(|cell| {
                    let bytes = hex::decode(&cell[2..]).expect("should decode cell bytes");

                    try_convert_to_cell::<P>(bytes)
                        .expect("test output cell bytes should fit into BYTES_PER_CELL bytes")
                })
                .collect::<Vec<_>>();

            let proofs = proofs_str
                .iter()
                .map(|proof| {
                    serde_yaml::from_str(proof).expect("should deserialize test output to proof")
                })
                .collect::<Vec<_>>();

            (cells, proofs)
        })
    }
}
