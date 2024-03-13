use std::collections::VecDeque;

use types::{
    altair::{consts::PARTICIPATION_FLAG_WEIGHTS, primitives::ParticipationFlags},
    combined::BeaconState,
    phase0::containers::Attestation,
    preset::Preset,
};

// trait HasEdge
// {
//     type Vertex;
//     fn is_compatible(&self, vertex1: Vertex, vertex2: Vertex) -> bool;
// }

// impl HasEdge for

pub struct MaxClique;

impl MaxClique {
    pub fn new() -> Self {
        Self {}
    }

    fn is_compatible<P: Preset>(att1: &Attestation<P>, att2: &Attestation<P>) -> bool {
        att1.data == att2.data && (att1.aggregation_bits.any_in_common(&att2.aggregation_bits))
    }

    pub fn find_maximal_attestation_cliques<P: Preset>(
        &self,
        attestations: Vec<Attestation<P>>,
    ) -> Vec<Vec<Attestation<P>>> {
        return Self::bron_kerbosch(&attestations);
    }

    // This needs some sort of bounding/pruning as it can generate (N/k)^k maximal cliques for N vertices
    // And this is is at least 2^(N/2) (with k = N / 2) or sqrt(N)^(sqrt(N)) (k = sqrt(N)), where both are at least exponential.
    // The construction for that: 1. divide N vertices to k bins of similar size 2. connect vertices in different pools.
    // As a graph contains maximal cliques where each vertex is from different bin.
    // Also it it seems that a full graph might take n! time.
    fn bron_kerbosch<P: Preset>(vertices: &Vec<Attestation<P>>) -> Vec<Vec<Attestation<P>>> {
        let mut answer = Vec::new();
        let mut vertex_deque = VecDeque::new();
        for vertex in vertices {
            vertex_deque.push_back(vertex.clone());
        }
        Self::bron_kerbosch_aux(&mut Vec::new(), vertex_deque, Vec::new(), &mut answer);
        answer
    }

    fn bron_kerbosch_aux<P: Preset>(
        cur_clique: &mut Vec<Attestation<P>>,
        mut pos_next: VecDeque<Attestation<P>>,
        mut not_chosen: Vec<Attestation<P>>,
        answer: &mut Vec<Vec<Attestation<P>>>,
    ) {
        if pos_next.len() == 0 && not_chosen.len() == 0 {
            answer.push(cur_clique.to_vec());
        }

        while !pos_next.is_empty() {
            let p = pos_next[0].clone();
            cur_clique.push(p.clone());
            pos_next.pop_front();
            let new_pos_next = pos_next
                .clone()
                .into_iter()
                .filter(|x| Self::is_compatible(&x, &p))
                .collect();
            let new_not_chosen = not_chosen
                .clone()
                .into_iter()
                .filter(|x| Self::is_compatible(&x, &p))
                .collect();
            Self::bron_kerbosch_aux(cur_clique, new_pos_next, new_not_chosen, answer);
            not_chosen.push(p.clone());
            cur_clique.pop();
        }
    }
}

// mod tests {
//     use crate::attestation_agg_pool::max_clique::MaxClique;

//     fn build_attestations(vertices: Vec<usize>, edges: Vec<Vec<usize>>)
//     {

//     }

//     #[test]
//     fn bron_kerbosch_small_test() {
//         let vertices: Vec<usize> = (0..7).collect();
//         let edges = [
//             (0, 1),
//             (0, 2),
//             (0, 3),
//             (1, 2),
//             (1, 3),
//             (2, 3),
//             (0, 4),
//             (4, 5),
//             (4, 6),
//             (1, 6),
//             (0, 6),
//             (4, 6),
//         ];

//         let is_compatible = |first: &usize, second: &usize| -> bool {
//             edges.contains(&(*first, *second)) || edges.contains(&(*first, *second))
//         };

//         // println!("{:?}", MaxClique::bron_kerbosch(&vertices, &is_compatible));
//     }
// }
