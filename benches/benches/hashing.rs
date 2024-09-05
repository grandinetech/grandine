// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use allocator as _;
use bls::{PublicKeyBytes, SignatureBytes};
use criterion::{Bencher, Criterion, Throughput};
use openssl::sha::Sha256 as OpenSslSha256;
use sha2::{Digest as _, Sha256 as Sha2Sha256};
use tap::Conv as _;
use types::phase0::primitives::H256;

// Criterion macros only add confusion.
fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    criterion
        .benchmark_group("64 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_64", hash_a(hashing::hash_64))
        .bench_function("sha2::Sha256", hash_a(sha2_hash_64))
        .bench_function("openssl::sha::sha256", hash_a(openssl_hash_64));

    criterion
        .benchmark_group("256 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_256", hash_a(hashing::hash_256))
        .bench_function("sha2::Sha256", hash_a(sha2_hash_256))
        .bench_function("openssl::sha::sha256", hash_a(openssl_hash_256));

    criterion
        .benchmark_group("256 + 8 = 264 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_256_8", hash_a_b(hashing::hash_256_8))
        .bench_function("sha2::Sha256", hash_a_b(sha2_hash_256_8))
        .bench_function("openssl::sha::Sha256", hash_a_b(openssl_hash_256_8));

    criterion
        .benchmark_group("256 + 8 + 32 = 296 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_256_8_32", hash_a_b_c(hashing::hash_256_8_32))
        .bench_function("sha2::Sha256", hash_a_b_c(sha2_hash_256_8_32))
        .bench_function("openssl::sha::Sha256", hash_a_b_c(openssl_hash_256_8_32));

    criterion
        .benchmark_group("256 + 64 = 320 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_256_64", hash_a_b(hashing::hash_256_64))
        .bench_function("sha2::Sha256", hash_a_b(sha2_hash_256_64))
        .bench_function("openssl::sha::Sha256", hash_a_b(openssl_hash_256_64));

    criterion
        .benchmark_group("32 + 64 + 256 = 352 bits")
        .throughput(Throughput::Elements(1))
        .bench_function(
            "hashing::hash_32_64_256",
            hash_a_b_c(hashing::hash_32_64_256),
        )
        .bench_function("sha2::Sha256", hash_a_b_c(sha2_hash_32_64_256))
        .bench_function("openssl::sha::Sha256", hash_a_b_c(openssl_hash_32_64_256));

    criterion
        .benchmark_group("384 bits")
        .throughput(Throughput::Elements(1))
        .bench_function(
            "hashing::hash_384",
            hash_a::<PublicKeyBytes>(hashing::hash_384),
        )
        .bench_function("sha2::Sha256", hash_a(sha2_hash_384))
        .bench_function("openssl::sha::sha256", hash_a(openssl_hash_384));

    criterion
        .benchmark_group("256 + 256 = 512 bits")
        .throughput(Throughput::Elements(1))
        .bench_function("hashing::hash_256_256", hash_a_b(hashing::hash_256_256))
        .bench_function("sha2::Sha256", hash_a_b(sha2_hash_256_256))
        .bench_function("openssl::sha::Sha256", hash_a_b(openssl_hash_256_256));

    criterion
        .benchmark_group("768 bits")
        .throughput(Throughput::Elements(1))
        .bench_function(
            "hashing::hash_768",
            hash_a::<SignatureBytes>(hashing::hash_768),
        )
        .bench_function("sha2::Sha256", hash_a(sha2_hash_768))
        .bench_function("openssl::sha::sha256", hash_a(openssl_hash_768));

    criterion.final_summary();
}

// Arrays of arbitrary length do not implement `Default` as of Rust 1.80.1.
// See <https://github.com/rust-lang/rust/issues/61415>.
// We work around that by using `PublicKeyBytes` and `SignatureBytes` instead.

fn hash_a<A: Default>(implementation: fn(A) -> H256) -> impl Fn(&mut Bencher) {
    move |bencher| bencher.iter(|| implementation(core::hint::black_box(A::default())))
}

fn hash_a_b<A: Default, B: Default>(implementation: fn(A, B) -> H256) -> impl Fn(&mut Bencher) {
    move |bencher| {
        bencher.iter(|| {
            implementation(
                core::hint::black_box(A::default()),
                core::hint::black_box(B::default()),
            )
        })
    }
}

fn hash_a_b_c<A: Default, B: Default, C: Default>(
    implementation: fn(A, B, C) -> H256,
) -> impl Fn(&mut Bencher) {
    move |bencher| {
        bencher.iter(|| {
            implementation(
                core::hint::black_box(A::default()),
                core::hint::black_box(B::default()),
                core::hint::black_box(C::default()),
            )
        })
    }
}

fn sha2_hash_64(value: u64) -> H256 {
    H256(Sha2Sha256::digest(value.to_le_bytes()).into())
}

fn sha2_hash_256(bytes: H256) -> H256 {
    H256(Sha2Sha256::digest(bytes).into())
}

fn sha2_hash_256_8(a: H256, b: u8) -> H256 {
    Sha2Sha256::new()
        .chain_update(a)
        .chain_update([b])
        .finalize()
        .conv::<[u8; H256::len_bytes()]>()
        .into()
}

fn sha2_hash_256_8_32(a: H256, b: u8, c: u32) -> H256 {
    Sha2Sha256::new()
        .chain_update(a)
        .chain_update([b])
        .chain_update(c.to_le_bytes())
        .finalize()
        .conv::<[u8; H256::len_bytes()]>()
        .into()
}

fn sha2_hash_256_64(a: H256, b: u64) -> H256 {
    Sha2Sha256::new()
        .chain_update(a)
        .chain_update(b.to_le_bytes())
        .finalize()
        .conv::<[u8; H256::len_bytes()]>()
        .into()
}

fn sha2_hash_32_64_256(a: [u8; 4], b: u64, c: H256) -> H256 {
    Sha2Sha256::new()
        .chain_update(a)
        .chain_update(b.to_le_bytes())
        .chain_update(c)
        .finalize()
        .conv::<[u8; H256::len_bytes()]>()
        .into()
}

fn sha2_hash_384(bytes: PublicKeyBytes) -> H256 {
    H256(Sha2Sha256::digest(bytes).into())
}

fn sha2_hash_256_256(left: H256, right: H256) -> H256 {
    Sha2Sha256::new()
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .conv::<[u8; H256::len_bytes()]>()
        .into()
}

fn sha2_hash_768(bytes: SignatureBytes) -> H256 {
    H256(Sha2Sha256::digest(bytes).into())
}

fn openssl_hash_64(value: u64) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(&value.to_le_bytes());
    hasher.finish().into()
}

fn openssl_hash_256(bytes: H256) -> H256 {
    openssl::sha::sha256(bytes.as_bytes()).into()
}

fn openssl_hash_256_8(a: H256, b: u8) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(a.as_bytes());
    hasher.update(&[b]);
    hasher.finish().into()
}

fn openssl_hash_256_8_32(a: H256, b: u8, c: u32) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(a.as_bytes());
    hasher.update(&[b]);
    hasher.update(&c.to_le_bytes());
    hasher.finish().into()
}

fn openssl_hash_256_64(a: H256, b: u64) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(a.as_bytes());
    hasher.update(&b.to_le_bytes());
    hasher.finish().into()
}

fn openssl_hash_32_64_256(a: [u8; 4], b: u64, c: H256) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(&a);
    hasher.update(&b.to_le_bytes());
    hasher.update(c.as_bytes());
    hasher.finish().into()
}

fn openssl_hash_384(bytes: PublicKeyBytes) -> H256 {
    openssl::sha::sha256(bytes.as_bytes()).into()
}

fn openssl_hash_256_256(left: H256, right: H256) -> H256 {
    let mut hasher = OpenSslSha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.finish().into()
}

fn openssl_hash_768(bytes: SignatureBytes) -> H256 {
    openssl::sha::sha256(bytes.as_bytes()).into()
}
