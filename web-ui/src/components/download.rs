//! Saving bytes held in the page as a file.

use gloo_timers::callback::Timeout;
use wasm_bindgen::{JsCast, JsValue};

/// Save bytes as a file through a temporary object URL.
pub fn download_bytes(filename: &str, bytes: &[u8], mime: &str) -> Result<(), String> {
    let js_error = |e: JsValue| e.as_string().unwrap_or_else(|| "browser error".to_string());

    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type(mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .map_err(js_error)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(js_error)?;

    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "no document".to_string())?;
    let body = document.body().ok_or_else(|| "no page body".to_string())?;
    let anchor = document
        .create_element("a")
        .map_err(js_error)?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "could not create a download link".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    body.append_child(&anchor).map_err(js_error)?;
    anchor.click();
    let _ = body.remove_child(&anchor);

    // Revoke after the browser has started the download.
    Timeout::new(1_000, move || {
        let _ = web_sys::Url::revoke_object_url(&url);
    })
    .forget();
    Ok(())
}
