use core::{cell::RefCell, time::Duration};
use std::{
    collections::HashMap,
    env::{self, VarError},
    io::Read as _,
    path::Path,
    sync::Arc,
};

use fs_err::File;
use reqwest::{blocking::Client, header::ACCEPT};
use ssz::SszRead;
use std_ext::ArcExt as _;
use types::{
    combined::BeaconState, config::Config, phase0::primitives::Slot, preset::Mainnet,
    redacting_url::RedactingUrl,
};

const SLOT_PLACEHOLDER: &str = "{slot}";
const EXAMPLE_REMOTE_URL: &str =
    "https://<archival-node-ip>:5052/eth/v2/debug/beacon/states/{slot}";

thread_local! {
    static STATE_CACHE: RefCell<HashMap<Slot, Arc<BeaconState<Mainnet>>>> = RefCell::new(HashMap::new());
}

pub fn state(slot: Slot) -> Arc<BeaconState<Mainnet>> {
    if let Some(cached) = STATE_CACHE.with_borrow(|cache| cache.get(&slot).cloned()) {
        return cached;
    }

    let asset_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/assets");
    let state_path = asset_dir.join(format!("{slot}.ssz"));

    if let Ok(mut state_file) = File::open(&state_path) {
        let mut buffer = Vec::new();
        state_file.read_to_end(&mut buffer).unwrap_or_else(|_| {
            panic!(
                "failed to read cached state file at {}",
                state_path.display()
            )
        });

        match Arc::<BeaconState<Mainnet>>::from_ssz(&Config::mainnet(), &buffer) {
            Ok(state) => {
                STATE_CACHE.with_borrow_mut(|cache| cache.insert(slot, state.clone_arc()));

                return state;
            }
            Err(error) => panic!(
                "failed to parse cached state at {}: {error:?}. \
                 Delete it to have the benchmark download the state again.",
                state_path.display(),
            ),
        }
    }

    let url = match env::var("REMOTE_URL") {
        Ok(url) => {
            assert!(
                url.contains(SLOT_PLACEHOLDER),
                "environment variable `REMOTE_URL` has invalid format. \
                It must contain a {SLOT_PLACEHOLDER} placeholder, for downloading \
                the state for a specific slot, for example: {EXAMPLE_REMOTE_URL}"
            );

            url.replace(SLOT_PLACEHOLDER, slot.to_string().as_str())
                .parse::<RedactingUrl>()
                .expect("environment variable `REMOTE_URL` must be a valid URL.")
        }
        Err(VarError::NotPresent) => {
            panic!(
                "please provide environment variable `REMOTE_URL`, to enable \
                fetching states remotely. It has to be in URL format, with \
                {SLOT_PLACEHOLDER} used as a placeholder for slot, \
                for example: {EXAMPLE_REMOTE_URL}"
            );
        }
        Err(VarError::NotUnicode(_)) => {
            panic!(
                "please provide valid unicode value for `REMOTE_URL` environment \
                variable. It has to be in URL format, with {SLOT_PLACEHOLDER} used \
                as a placeholder for slot, for example: {EXAMPLE_REMOTE_URL}"
            )
        }
    };

    let url = url.into_url();

    let client = Client::builder()
        .timeout(Duration::from_mins(10))
        .build()
        .expect("failed to build HTTP client for downloading states");

    let response = match client
        .get(url)
        .header(ACCEPT, "application/octet-stream")
        .send()
    {
        Ok(response) => response,
        Err(error) => panic!("request for slot {slot} failed with error {error:?}."),
    };

    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(error) => panic!(
            "remote service returned error {error:?}, \
            while trying to fetch state at slot {slot}"
        ),
    };

    let response = match response.bytes() {
        Ok(response) => response,
        Err(error) => {
            panic!("failed to read state at slot {slot} from remote, with error {error:?}")
        }
    };

    let bytes = response.to_vec();

    let state =
        Arc::<BeaconState<Mainnet>>::from_ssz(&Config::mainnet(), &bytes).unwrap_or_else(|_| {
            panic!(
                "failed to parse state, received from remote for slot {slot} - \
                 received bytes is not a valid SSZ-serialized state"
            )
        });

    STATE_CACHE.with_borrow_mut(|cache| cache.insert(slot, state.clone_arc()));

    fs_err::write(state_path, bytes).expect("failed to save downloaded state from remote");

    state
}

// just any state, at the start of epoch, that will be used for benchmarking
// against different scenarios.
const BASE: Slot = 14_319_872;
const SLOTS_PER_EPOCH: u64 = 32;

pub const PAIRS: [(&str, Slot, Slot); 8] = [
    ("epochs +1", BASE, BASE + SLOTS_PER_EPOCH),
    ("epochs +2", BASE, BASE + 2 * SLOTS_PER_EPOCH),
    ("epochs +31", BASE, BASE + 31 * SLOTS_PER_EPOCH),
    ("epochs +32", BASE, BASE + 32 * SLOTS_PER_EPOCH),
    ("epochs +128", BASE, BASE + 128 * SLOTS_PER_EPOCH),
    ("slot +1", BASE, BASE + 1),
    ("slot +31", BASE, BASE + SLOTS_PER_EPOCH - 1),
    ("epochs +56369", 13_164_544, 14_968_352),
];
