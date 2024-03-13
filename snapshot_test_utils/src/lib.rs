use core::ops::Range;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context as _, Error, Result};
use assert_json_diff::{CompareMode, Config as CompareConfig};
use bstr::ByteSlice as _;
use derive_more::From;
use fs_err::tokio::{File, OpenOptions};
use futures::stream::{StreamExt as _, TryStreamExt as _};
use http::{header::DATE, Version};
use httparse::{Header, Request, Response, Status, EMPTY_HEADER};
use itertools::Itertools as _;
use serde_json::Value;
use tap::Pipe as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

// Limit the number of headers to the same value as `hyper`.
// Parsing into a `Vec` with `httparse` would take more work.
// We wouldn't be able to submit requests with more than this anyway.
const MAX_HEADERS: usize = 100;
const EMPTY_HEADERS: [Header; MAX_HEADERS] = [EMPTY_HEADER; MAX_HEADERS];

// The `Date` header is nondeterministic but semi-required in responses.
// `hyper` sets it based on `SystemTime::now` and provides no way to override it. See:
// - <https://datatracker.ietf.org/doc/html/rfc7231>
// - <https://github.com/hyperium/hyper/issues/912>
// - <https://github.com/hyperium/hyper/pull/2751>
// We replace its value with a deterministic one: the Unix epoch.
// We use a valid date to retain compatibility with other tools.
const NORMALIZED_DATE: &str = "Thu, 01 Jan 1970 00:00:00 GMT";

#[derive(Clone, Copy, From)]
pub struct Case<'path> {
    case_path_relative_to_workspace_root: &'path str,
}

impl<'path> Case<'path> {
    pub async fn run(self, update_responses: bool, address: SocketAddr) -> Result<()> {
        self.submit_requests(update_responses, address)
            .await
            .with_context(|| format!("test case {} failed", self.file_name()))
    }

    async fn submit_requests(self, update_responses: bool, address: SocketAddr) -> Result<()> {
        let results =
            self.glob("*.request")
                .pipe(futures::stream::iter)
                .then(|request_path| async move {
                    let request_name = request_path
                        .file_stem()
                        .ok_or_else(|| Error::msg("request name should not be empty"))?
                        .to_str()
                        .ok_or_else(|| Error::msg("request name should be a valid UTF-8 string"))?;

                    self.submit_single_request(update_responses, address, request_path.as_path())
                        .await
                        .with_context(|| format!("request {request_name} failed"))
                });

        // The `*read-only` test cases exist to save resources, but they make debugging harder.
        // Treat them specially by always running all requests in them and reporting all errors.
        // This should still be faster than having individual test cases for each request.
        // This assumes the requests are in fact read-only.
        if self.ends_with("read-only") {
            let (successes, failures): (Vec<()>, Vec<_>) = results
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .partition_result();

            let separator = "\n\n";

            ensure!(
                failures.is_empty(),
                "{}/{} requests failed{separator}{:?}",
                failures.len(),
                successes.len() + failures.len(),
                failures.into_iter().format(separator),
            );

            Ok(())
        } else {
            results.try_collect().await
        }
    }

    async fn submit_single_request(
        self,
        update_responses: bool,
        address: SocketAddr,
        request_path: &Path,
    ) -> Result<()> {
        let mut request_file = self.file_for_reading(request_path).await;

        let request_length = request_file.metadata().await?.len().try_into()?;

        let mut request_bytes = Vec::with_capacity(request_length);

        request_file.read_to_end(&mut request_bytes).await?;

        validate_request(request_bytes.as_slice()).context("request is not valid")?;

        let mut stream = TcpStream::connect(address).await?;

        stream.write_all(request_bytes.as_slice()).await?;

        let response_path = request_path.with_extension("response");

        let mut response_file = if update_responses {
            self.file_for_writing(response_path).await
        } else {
            self.file_for_reading(response_path).await
        };

        let expected_response_length = response_file.metadata().await?.len().try_into()?;

        let mut actual_bytes = Vec::with_capacity(expected_response_length);

        // Do not make assertions about the actual length of the response.
        // It only gets in the way of debugging.
        stream.read_to_end(&mut actual_bytes).await?;

        normalize_response_headers(&mut actual_bytes)?;
        normalize_response_body(&mut actual_bytes)?;

        if update_responses {
            response_file.write_all(actual_bytes.as_slice()).await?;
            return Ok(());
        }

        let mut expected_bytes = Vec::with_capacity(expected_response_length);

        response_file.read_to_end(&mut expected_bytes).await?;

        compare_responses(actual_bytes.as_slice(), expected_bytes.as_slice())
    }

    fn file_name(self) -> &'path str {
        self.case_path_relative_to_workspace_root
            .rsplit_once('/')
            .map(|(_, suffix)| suffix)
            .unwrap_or(self.case_path_relative_to_workspace_root)
    }

    fn ends_with(self, suffix: &str) -> bool {
        self.case_path_relative_to_workspace_root.ends_with(suffix)
    }

    fn glob(self, relative_pattern: &str) -> impl Iterator<Item = PathBuf> + 'path {
        let owned_pattern = self.resolve(relative_pattern);

        let pattern = owned_pattern
            .to_str()
            .expect("pattern is formed by concatenating UTF-8 strings");

        glob::glob(pattern)
            .expect("pattern should be valid")
            .map(move |result| self.unresolve(result.expect("every path should be accessible")))
    }

    async fn file_for_reading(self, file_name: impl AsRef<Path> + Send) -> File {
        File::open(self.resolve(file_name))
            .await
            .expect("could not open file for reading")
    }

    async fn file_for_writing(self, file_name: impl AsRef<Path> + Send) -> File {
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(self.resolve(file_name))
            .await
            .expect("could not open file for writing")
    }

    fn resolve(self, relative_path: impl AsRef<Path>) -> PathBuf {
        workspace_root_relative_to_tested_crate_root()
            .join(self.case_path_relative_to_workspace_root)
            .join(relative_path)
    }

    fn unresolve(self, path: impl AsRef<Path>) -> PathBuf {
        path.as_ref()
            .strip_prefix(workspace_root_relative_to_tested_crate_root())
            .expect(
                "paths produced by Case::resolve start with components leading to workspace root",
            )
            .strip_prefix(self.case_path_relative_to_workspace_root)
            .expect("paths produced by Case::resolve contain case path")
            .to_path_buf()
    }
}

fn validate_request(bytes: &[u8]) -> Result<()> {
    let mut headers = EMPTY_HEADERS;

    let (request, _) = parse_request(bytes, &mut headers)?;

    // A test runner that supports later versions would take more work.
    // HTTP/1.1 is complicated due to persistent connections and chunked transfer encoding.
    // `hyper` doesn't allow half-closed connections by default, though they can be enabled.
    // A client must read the response before shutting down the write half of the connection.
    // Chunked transfer encoding in responses also makes it harder to diff response bodies as JSON.
    // The iteration order of `http::HeaderMap` is not suitable for snapshot testing.
    // Using a HTTP/1.0-like format for later versions may help but would require a lot of DIY.
    ensure!(
        request.version == Some(0),
        "snapshot test runner only supports {:?}",
        Version::HTTP_10,
    );

    Ok(())
}

fn normalize_response_headers(bytes: &mut Vec<u8>) -> Result<()> {
    // Loop for 2 reasons:
    // - Modifying `bytes` invalidates the references in `response`.
    // - A header may occur in the response multiple times.
    'outer: loop {
        let mut headers = EMPTY_HEADERS;

        let (response, _) = parse_response(bytes, &mut headers)?;

        for header in response.headers.iter() {
            // The name comparison ignores case, just like `str::eq_ignore_ascii_case`.
            if header.name == DATE && header.value != NORMALIZED_DATE.as_bytes() {
                let Range { start, end } = header.value.as_ptr_range();
                let start_offset = start as usize - bytes.as_slice().as_ptr() as usize;
                let end_offset = end as usize - bytes.as_slice().as_ptr() as usize;

                bytes.splice(start_offset..end_offset, NORMALIZED_DATE.bytes());

                continue 'outer;
            }
        }

        break;
    }

    Ok(())
}

fn normalize_response_body(bytes: &mut Vec<u8>) -> Result<()> {
    let mut headers = EMPTY_HEADERS;

    let (_, body) = parse_response(bytes, &mut headers)?;

    // If the response body is valid JSON, pretty-print it.
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        let body_offset = bytes.len() - body.len();
        let pretty_printed = serde_json::to_string_pretty(&json)?;

        bytes.truncate(body_offset);
        bytes.extend_from_slice(pretty_printed.as_bytes());
    }

    Ok(())
}

fn compare_responses(actual_bytes: &[u8], expected_bytes: &[u8]) -> Result<()> {
    // Compare bytes first to speed up the successful path.
    // If that fails, compare the responses in a finer-grained manner for better error messages.
    if actual_bytes == expected_bytes {
        return Ok(());
    }

    let mut actual_headers = EMPTY_HEADERS;
    let mut expected_headers = EMPTY_HEADERS;

    let (actual_response, actual_body) = parse_response(actual_bytes, &mut actual_headers)
        .context("actual response is not valid")?;

    let (expected_response, expected_body) = parse_response(expected_bytes, &mut expected_headers)
        .context("expected response is not valid")?;

    compare_response_status_lines(&actual_response, &expected_response)?;

    // Compare bodies before headers.
    // It's typically more useful to see differences in the body than `Content-Length`.
    compare_response_bodies(actual_body, expected_body)?;

    compare_response_headers(actual_response.headers, expected_response.headers)
}

fn compare_response_status_lines(
    actual_response: &Response,
    expected_response: &Response,
) -> Result<()> {
    let actual_version = unwrap_response_field(actual_response.version);
    let actual_code = unwrap_response_field(actual_response.code);
    let actual_reason = unwrap_response_field(actual_response.reason);
    let expected_version = unwrap_response_field(expected_response.version);
    let expected_code = unwrap_response_field(expected_response.code);
    let expected_reason = unwrap_response_field(expected_response.reason);

    ensure!(
        actual_version == expected_version,
        "response versions do not match (actual: {actual_version}, expected: {expected_version})",
    );

    ensure!(
        actual_code == expected_code,
        "response status codes do not match (actual: {actual_code}, expected: {expected_code})",
    );

    ensure!(
        actual_reason == expected_reason,
        "response reasons do not match (actual: {actual_reason:?}, expected: {expected_reason:?})",
    );

    Ok(())
}

fn compare_response_headers(actual_headers: &[Header], expected_headers: &[Header]) -> Result<()> {
    let actual_names = actual_headers.iter().map(|header| header.name);
    let expected_names = expected_headers.iter().map(|header| header.name);

    // If all headers have the same names,
    // compare their values individually for better error messages.
    if actual_names.eq(expected_names) {
        for (actual_header, expected_header) in actual_headers.iter().zip(expected_headers) {
            let name = actual_header.name;
            let actual_bstr = actual_header.value.as_bstr();
            let expected_bstr = expected_header.value.as_bstr();

            ensure!(
                actual_bstr == expected_bstr,
                "values of response header {name} do not match \
                 (actual: {actual_bstr:?}, expected: {expected_bstr:?})",
            );
        }
    } else {
        ensure!(
            actual_headers == expected_headers,
            "response headers do not match \
             (actual: {actual_headers:?}, expected: {expected_headers:?})",
        );
    }

    Ok(())
}

fn compare_response_bodies(actual_bytes: &[u8], expected_bytes: &[u8]) -> Result<()> {
    let actual_json_option = serde_json::from_slice::<Value>(actual_bytes).ok();
    let expected_json_option = serde_json::from_slice::<Value>(expected_bytes).ok();

    // If both response bodies are valid JSON, diff them structurally.
    if let Some((actual_json, expected_json)) = actual_json_option.zip(expected_json_option) {
        // Do not return early if the bodies are equal when compared as JSON.
        // They may be formatted differently.
        assert_json_diff::assert_json_matches_no_panic(
            &actual_json,
            &expected_json,
            CompareConfig::new(CompareMode::Strict),
        )
        .map_err(Error::msg)?;
    }

    let actual_bstr = actual_bytes.as_bstr();
    let expected_bstr = expected_bytes.as_bstr();

    ensure!(
        actual_bstr == expected_bstr,
        "response bodies do not match (actual: {actual_bstr:?}, expected: {expected_bstr:?})"
    );

    Ok(())
}

fn parse_request<'b, 'h>(
    bytes: &'b [u8],
    headers: &'h mut [Header<'b>],
) -> Result<(Request<'h, 'b>, &'b [u8])> {
    let mut request = Request {
        method: None,
        path: None,
        version: None,
        headers,
    };

    let body_offset = match request.parse(bytes)? {
        Status::Complete(offset) => offset,
        Status::Partial => bail!("request is incomplete"),
    };

    let body = &bytes[body_offset..];

    Ok((request, body))
}

fn parse_response<'b, 'h>(
    bytes: &'b [u8],
    headers: &'h mut [Header<'b>],
) -> Result<(Response<'h, 'b>, &'b [u8])> {
    let mut response = Response {
        version: None,
        code: None,
        reason: None,
        headers,
    };

    let body_offset = match response.parse(bytes)? {
        Status::Complete(offset) => offset,
        Status::Partial => bail!("response is incomplete"),
    };

    let body = &bytes[body_offset..];

    Ok((response, body))
}

fn unwrap_response_field<T>(option: Option<T>) -> T {
    option.expect("httparse sets Response fields to Some if response is valid")
}

// This is needed to make `Case` work with `test_generator::test_resources`.
// Cargo runs procedural macros and tests in different working directories.
// Procedural macros are run in the workspace root.
// Tests are run in the crate root.
// See <https://github.com/frehberg/test-generator/issues/6>.
//
// `env!("CARGO_MANIFEST_DIR")` expands to the absolute path of `snapshot_test_utils`.
// As a result, this crate will not work correctly when used from other workspaces.
fn workspace_root_relative_to_tested_crate_root() -> PathBuf {
    let mut workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    assert!(workspace_root.pop());

    let tested_crate_root =
        std::env::current_dir().expect("current directory should exist and be accessible");

    pathdiff::diff_paths(workspace_root, tested_crate_root)
        .expect("snapshot_test_utils should only be used by crates inside the same workspace")
}
