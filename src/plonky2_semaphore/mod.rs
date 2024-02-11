use std::time::Instant;

use colored::Colorize;

pub mod access_set;
pub mod circuit;
pub mod recursion;
pub mod signal;

fn report_elapsed(now: Instant) {
    println!(
        "{}",
        format!("Took {} milliseconds", now.elapsed().as_millis())
            .blue()
            .bold()
    );
}
