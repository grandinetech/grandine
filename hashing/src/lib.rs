use ethereum_types::H256;
use generic_array::GenericArray;
use hex_literal::hex;
use sha2::{
    digest::{core_api::BlockSizeUser, generic_array::typenum::Unsigned as _},
    Sha256,
};

#[rustfmt::skip]
pub const ZERO_HASHES: [H256; 41] = [
    H256(hex!("0000000000000000000000000000000000000000000000000000000000000000")),
    H256(hex!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")),
    H256(hex!("db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71")),
    H256(hex!("c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c")),
    H256(hex!("536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c")),
    H256(hex!("9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30")),
    H256(hex!("d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1")),
    H256(hex!("87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c")),
    H256(hex!("26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193")),
    H256(hex!("506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1")),
    H256(hex!("ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b")),
    H256(hex!("6cf04127db05441cd833107a52be852868890e4317e6a02ab47683aa75964220")),
    H256(hex!("b7d05f875f140027ef5118a2247bbb84ce8f2f0f1123623085daf7960c329f5f")),
    H256(hex!("df6af5f5bbdb6be9ef8aa618e4bf8073960867171e29676f8b284dea6a08a85e")),
    H256(hex!("b58d900f5e182e3c50ef74969ea16c7726c549757cc23523c369587da7293784")),
    H256(hex!("d49a7502ffcfb0340b1d7885688500ca308161a7f96b62df9d083b71fcc8f2bb")),
    H256(hex!("8fe6b1689256c0d385f42f5bbe2027a22c1996e110ba97c171d3e5948de92beb")),
    H256(hex!("8d0d63c39ebade8509e0ae3c9c3876fb5fa112be18f905ecacfecb92057603ab")),
    H256(hex!("95eec8b2e541cad4e91de38385f2e046619f54496c2382cb6cacd5b98c26f5a4")),
    H256(hex!("f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17f")),
    H256(hex!("cddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaa")),
    H256(hex!("8a8d7fe3af8caa085a7639a832001457dfb9128a8061142ad0335629ff23ff9c")),
    H256(hex!("feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167")),
    H256(hex!("e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d7")),
    H256(hex!("31206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc0")),
    H256(hex!("21352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544")),
    H256(hex!("619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a46765")),
    H256(hex!("7cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4")),
    H256(hex!("848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe1")),
    H256(hex!("8869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636")),
    H256(hex!("b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c")),
    H256(hex!("985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7")),
    // The rest of these are only needed for hashing validator and balance lists in `BeaconState`.
    H256(hex!("c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff")),
    H256(hex!("1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc5")),
    H256(hex!("2f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d")),
    H256(hex!("328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362c")),
    H256(hex!("bfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c327")),
    H256(hex!("55d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74")),
    H256(hex!("f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76")),
    H256(hex!("ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f")),
    // `ZERO_HASHES[40]` is needed to run `consensus-spec-tests`.
    // It is used when `BeaconState.validators` is empty.
    // It should never be used in normal operation.
    H256(hex!("6bfe8d2bcc4237b74a5047058ef455339ecd7360cb63bfbb8ee5448e6430ba04")),
];

// Surprisingly, hardcoding the padding is enough to yield a significant speedup.
// Precomputing its schedule and using it directly in `sha2` has next to no effect,
// though that may be due to our lack of expertise with SIMD programming.
// Maybe the compiler is precomputing the message schedule on its own?
//
// Another surprise was that `sha2::Sha256` slows down significantly when LTO is enabled.
// `sha2::compress256` does not, so this crate is unaffected.

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_64_BITS: Sha256Block = hex!("
    00000000 00000000 80000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000040
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_128_BITS: Sha256Block = hex!("
    00000000 00000000 80000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000080
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_256_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    80000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000100
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_264_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00800000 00000000 00000000 00000000
    00000000 00000000 00000000 00000108
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_296_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00800000 00000000 00000000
    00000000 00000000 00000000 00000128
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_320_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 80000000 00000000
    00000000 00000000 00000000 00000140
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_352_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 80000000
    00000000 00000000 00000000 00000160
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_384_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    80000000 00000000 00000000 00000180
");

// This one has nothing but padding.
#[rustfmt::skip]
const PADDING_BLOCK_FOR_512_BITS: Sha256Block = hex!("
    80000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000200
");

#[rustfmt::skip]
const BLOCK_WITH_PADDING_FOR_768_BITS: Sha256Block = hex!("
    00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000
    80000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000300
");

type Sha256BlockSize = <Sha256 as BlockSizeUser>::BlockSize;
type Sha256Block = [u8; Sha256BlockSize::USIZE];

// `sha2::sha256::x86` uses SSE2 intrinsics that work with unaligned data.
// On recent CPUs they are faster when the data is actually aligned at runtime. See:
// - <https://stackoverflow.com/questions/39985820/assembly-movdqa-access-violation#comment67285405_40001662>
// - <https://stackoverflow.com/questions/40854819/is-there-any-situation-where-using-movdqu-and-movupd-is-better-than-movups/48708852#48708852>
// However, aligning the state and blocks explicitly with `#[repr(align(16))]` has no effect.
// The generated assembly is identical.
struct Sha256State([u32; 8]);

impl Default for Sha256State {
    #[rustfmt::skip]
    fn default() -> Self {
        Self([
            0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
            0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
        ])
    }
}

impl Sha256State {
    fn compress_single(self, block: Sha256Block) -> Self {
        self.compress_multiple(core::slice::from_ref(GenericArray::from_slice(&block)))
    }

    // Moving blocks into an array is faster than calling `sha2::compress256` multiple times.
    fn compress_multiple(mut self, blocks: &[GenericArray<u8, Sha256BlockSize>]) -> Self {
        sha2::compress256(&mut self.0, blocks);
        self
    }

    fn output(self) -> H256 {
        let mut output = H256::default();

        for (o, s) in output.as_bytes_mut().chunks_exact_mut(4).zip(self.0) {
            o.copy_from_slice(&s.to_be_bytes());
        }

        output
    }
}

#[inline]
#[must_use]
pub fn hash_64(value: u64) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_64_BITS;
    block[..8].copy_from_slice(&value.to_le_bytes());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_64_64(a: u64, b: u64) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_128_BITS;
    block[..8].copy_from_slice(&a.to_le_bytes());
    block[8..16].copy_from_slice(&b.to_le_bytes());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_256(bytes: H256) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_256_BITS;
    block[..32].copy_from_slice(bytes.as_bytes());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_256_8(a: H256, b: u8) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_264_BITS;
    block[..32].copy_from_slice(a.as_bytes());
    block[32] = b;

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_256_8_32(a: H256, b: u8, c: u32) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_296_BITS;
    block[..32].copy_from_slice(a.as_bytes());
    block[32] = b;
    block[32 + 1..32 + 1 + 4].copy_from_slice(&c.to_le_bytes());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_256_64(a: H256, b: u64) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_320_BITS;
    block[..32].copy_from_slice(a.as_bytes());
    block[32..32 + 8].copy_from_slice(&b.to_le_bytes());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_32_64_256(a: [u8; 4], b: u64, c: H256) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_352_BITS;
    block[..4].copy_from_slice(&a);
    block[4..4 + 8].copy_from_slice(&b.to_le_bytes());
    block[4 + 8..4 + 8 + 32].copy_from_slice(c.as_bytes());

    Sha256State::default().compress_single(block).output()
}

// This function is only ever called with `PublicKeyBytes`,
// but that can't be the type of the parameter due to a circular dependency.
#[inline]
#[must_use]
pub fn hash_384(bytes: impl AsRef<[u8; 48]>) -> H256 {
    let mut block = BLOCK_WITH_PADDING_FOR_384_BITS;
    block[..48].copy_from_slice(bytes.as_ref());

    Sha256State::default().compress_single(block).output()
}

#[inline]
#[must_use]
pub fn hash_256_256(left: H256, right: H256) -> H256 {
    let mut block = GenericArray::default();
    block[..32].copy_from_slice(left.as_bytes());
    block[32..].copy_from_slice(right.as_bytes());

    let padding_block = *GenericArray::from_slice(&PADDING_BLOCK_FOR_512_BITS);

    Sha256State::default()
        .compress_multiple(&[block, padding_block])
        .output()
}

// This function is only ever called with `SignatureBytes`,
// but that can't be the type of the parameter due to a circular dependency.
#[inline]
#[must_use]
pub fn hash_768(bytes: impl AsRef<[u8; 96]>) -> H256 {
    let mut block_1 = GenericArray::default();
    block_1.copy_from_slice(&bytes.as_ref()[..64]);

    let mut block_2 = *GenericArray::from_slice(&BLOCK_WITH_PADDING_FOR_768_BITS);
    block_2[..32].copy_from_slice(&bytes.as_ref()[64..]);

    Sha256State::default()
        .compress_multiple(&[block_1, block_2])
        .output()
}

#[cfg(test)]
mod tests {
    use itertools::Itertools as _;

    use super::*;

    #[test]
    fn higher_zero_hashes_are_calculated_from_lower_ones() {
        for (lower, higher) in ZERO_HASHES.into_iter().tuple_windows() {
            assert_eq!(hash_256_256(lower, lower), higher);
        }
    }
}
