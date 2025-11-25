#![expect(
    unused_crate_dependencies,
    reason = "The `unused_crate_dependencies` lint checks every crate in a package separately. \
              See <https://github.com/rust-lang/rust/issues/57274>."
)]

use features::{Feature, log};
//use log::Level;
use tracing_test::traced_test;

#[expect(clippy::string_slice)]
#[traced_test]
#[test]
fn feature_macro_produce_correct_output() {
    showcase();

    logs_assert(|lines: &[&str]| {
        use itertools::assert_equal;

        let log_lines: Vec<&str> = lines
            .iter()
            .map(|line| {
                let msg_start = line.find("Block processed in").unwrap_or(0);
                &line[msg_start..]
            })
            .collect();

        let expected_lines = [
            "Block processed in 1ms peers=[0/0] feature=LogBlockProcessingTime",
            "Block processed in 4ms peers=[0/0] feature=LogBlockProcessingTime",
            "Block processed in 1ms peers=[0/0] feature=LogBlockProcessingTime",
            "Block processed in 4ms peers=[0/0] feature=LogBlockProcessingTime",
        ];

        assert_equal(log_lines.iter(), expected_lines.iter());

        Ok(())
    });
}

fn showcase() {
    Feature::LogBlockProcessingTime.enable();

    if Feature::LogBlockProcessingTime.is_enabled() {
        // The expressions used in the message are only evaluated if the feature is enabled.
        log!(LogBlockProcessingTime, "Block processed in 1ms");
        log!(LogBlockProcessingTime, "Block processed in {}ms", 2 + 2);
    }

    // Using the full path may help avoid namespace clashes with `log::log!`.
    features::log!(LogBlockProcessingTime, "Block processed in 1ms");
    features::log!(LogBlockProcessingTime, "Block processed in {}ms", 2 + 2);
}
