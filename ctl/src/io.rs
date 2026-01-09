use anyhow::{Context, Result};
use serde::Serialize;

pub fn output<T: Serialize>(json_mode: bool, value: &T, pretty_fn: impl FnOnce(&T)) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        pretty_fn(value);
    }
}

pub fn output_slice<T: Serialize>(json_mode: bool, value: &[T], pretty_fn: impl FnOnce(&[T])) {
    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(value).unwrap_or_else(|_| "[]".to_string())
        );
    } else {
        pretty_fn(value);
    }
}

pub fn read_json_input(file: Option<&str>) -> Result<String> {
    match file {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("Failed to read file: {}", path))
        }
        None => {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .context("Failed to read from stdin")?;
            Ok(buffer)
        }
    }
}
