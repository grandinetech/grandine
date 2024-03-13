// The `unused_crate_dependencies` lint checks every crate in a package separately.
// See <https://github.com/rust-lang/rust/issues/57274>.
#![allow(unused_crate_dependencies)]

use features::{log, Feature};
use log::Level;

#[test]
fn both_syntaxes_produce_correct_output() {
    testing_logger::setup();

    showcase();

    testing_logger::validate(|logs| {
        itertools::assert_equal(
            logs.iter().map(|log| log.body.as_str()),
            core::iter::repeat([
                "[LogBlockProcessingTime] Block processed in 1ms",
                "[LogBlockProcessingTime] Block processed in 4ms",
            ])
            .take(3)
            .flatten(),
        );

        for log in logs {
            assert_eq!(log.level, Level::Info);
            assert_eq!(log.target, "features");
        }
    });
}

fn showcase() {
    Feature::LogBlockProcessingTime.enable();

    if Feature::LogBlockProcessingTime.is_enabled() {
        Feature::LogBlockProcessingTime.log("Block processed in 1ms");
    }
    if Feature::LogBlockProcessingTime.is_enabled() {
        Feature::LogBlockProcessingTime.log(format_args!("Block processed in {}ms", 2 + 2));
    }

    // This is a shorthand for the above.
    // The expressions used in the message are only evaluated if the feature is enabled.
    log!(LogBlockProcessingTime, "Block processed in 1ms");
    log!(LogBlockProcessingTime, "Block processed in {}ms", 2 + 2);

    // Using the full path may help avoid namespace clashes with `log::log!`.
    features::log!(LogBlockProcessingTime, "Block processed in 1ms");
    features::log!(LogBlockProcessingTime, "Block processed in {}ms", 2 + 2);
}
