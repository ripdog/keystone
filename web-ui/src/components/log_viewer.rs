//! Journal log viewer for the managed services.
//!
//! Shows the newest entries first, so the latest line is at the top. The viewer
//! polls with the journal cursor of the newest entry it has, which returns only
//! what is new; scrolling to the bottom loads older entries before the oldest
//! cursor; and jumping to a date reloads the log from that time backwards,
//! which turns streaming off until the viewer goes back to the latest entries.
//! The journald part of each line (time, service, process id) sits in its own
//! columns and is coloured, so the logged text stands alone in the last one.

use crate::api::{self, LogPage};
use crate::components::rule_table::{FilterBox, matches_filter};
use gloo_timers::callback::Interval;
use keystone_core::JournalEntry;
use leptos::html;
use leptos::prelude::*;
use leptos::task::spawn_local;

/// Entries requested per page.
const PAGE: usize = 200;
/// Entries kept in the page. Past this, the oldest ones are dropped as new ones
/// arrive, and scrolling down loads them again.
const MAX_ROWS: usize = 3000;
const POLL_MS: u32 = 2000;
/// Distance from the bottom, in pixels, at which older entries start loading.
const LOAD_OLDER_MARGIN: i32 = 300;

/// Colour of the logged text by syslog severity.
fn priority_class(priority: u8) -> &'static str {
    match priority {
        0..=3 => "text-red-300",
        4 => "text-amber-300",
        5 => "text-sky-300",
        7 => "text-slate-500",
        _ => "text-slate-200",
    }
}

/// Short severity name, for the hover text and the filter.
fn priority_name(priority: u8) -> &'static str {
    match priority {
        0 => "emergency",
        1 => "alert",
        2 => "critical",
        3 => "error",
        4 => "warning",
        5 => "notice",
        7 => "debug",
        _ => "info",
    }
}

/// The unit's name without `.service`.
fn short_unit(unit: &str) -> &str {
    unit.strip_suffix(".service").unwrap_or(unit)
}

/// A stable colour per service, so one service's lines are easy to follow.
fn unit_class(unit: &str) -> &'static str {
    const COLOURS: [&str; 6] = [
        "text-emerald-300",
        "text-violet-300",
        "text-cyan-300",
        "text-pink-300",
        "text-lime-300",
        "text-orange-300",
    ];
    let hash = unit.bytes().fold(7usize, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(byte.into())
    });
    COLOURS[hash % COLOURS.len()]
}

/// Local `(date, time)` of a journal timestamp, as `YYYY-MM-DD` and `HH:MM:SS`.
fn local_parts(realtime_us: u64) -> (String, String) {
    let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(
        (realtime_us / 1000) as f64,
    ));
    (
        format!(
            "{}-{:02}-{:02}",
            date.get_full_year(),
            date.get_month() + 1,
            date.get_date()
        ),
        format!(
            "{:02}:{:02}:{:02}",
            date.get_hours(),
            date.get_minutes(),
            date.get_seconds()
        ),
    )
}

/// Local `YYYY-MM-DD HH:MM:SS.mmm` of a journal timestamp.
fn local_full(realtime_us: u64) -> String {
    let (day, time) = local_parts(realtime_us);
    format!("{day} {time}.{:03}", (realtime_us / 1000) % 1000)
}

/// Microseconds since the epoch of a `datetime-local` value (local time), or
/// `None` when it is empty or not a date.
fn parse_local_datetime(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let millis = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(value)).get_time();
    (millis.is_finite() && millis >= 0.0).then(|| millis as u64 * 1000)
}

/// Entries newest first, from a page that is oldest first.
fn newest_first(mut entries: Vec<JournalEntry>) -> Vec<JournalEntry> {
    entries.reverse();
    entries
}

/// Put newly arrived entries (oldest first) in front of the rows (newest
/// first), and keep at most [`MAX_ROWS`]. True when old rows were dropped.
fn prepend_new(rows: &mut Vec<JournalEntry>, arrived: Vec<JournalEntry>) -> bool {
    let mut merged = newest_first(arrived);
    merged.append(rows);
    let dropped = merged.len() > MAX_ROWS;
    merged.truncate(MAX_ROWS);
    *rows = merged;
    dropped
}

#[component]
pub fn LogViewer(
    token: Signal<String>,
    on_unauthorized: Callback<()>,
    /// Managed units to show, such as `dnsmasq.service`.
    units: Signal<Vec<String>>,
    /// Show the service column. Off when the page is about one service.
    #[prop(default = true)]
    show_unit: bool,
) -> impl IntoView {
    // Newest first.
    let entries = RwSignal::new(Vec::<JournalEntry>::new());
    let paused = RwSignal::new(false);
    let filter = RwSignal::new(String::new());
    // Show the date and milliseconds in the time column, for lining entries up
    // with other logs.
    let full_time = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let cursor_reset = RwSignal::new(false);
    // Set while the view is a jump to a date; streaming is then off.
    let until = RwSignal::new(None::<u64>);
    let date_input = RwSignal::new(String::new());
    // The oldest entry is on screen: the journal has nothing before it.
    let at_start = RwSignal::new(false);
    let loading = RwSignal::new(false);
    let loading_older = StoredValue::new(false);
    let polling = StoredValue::new(false);
    // Bumped on every reload so a slow answer for an old view is dropped.
    let generation = StoredValue::new(0u64);
    let scroll_ref = NodeRef::<html::Div>::new();

    let fail = move |message: String| {
        if message.contains("Unauthorized") {
            on_unauthorized.run(());
        }
        error.set(Some(message));
    };

    // Replace the rows with the first page of the current view.
    let reload = move || {
        generation.update_value(|value| *value += 1);
        let current = generation.get_value();
        entries.set(Vec::new());
        at_start.set(false);
        cursor_reset.set(false);
        error.set(None);
        let token_value = token.get_untracked();
        let unit_list = units.get_untracked();
        if token_value.is_empty() || unit_list.is_empty() {
            loading.set(false);
            return;
        }
        let page = until
            .get_untracked()
            .map_or(LogPage::Newest, LogPage::Until);
        loading.set(true);
        spawn_local(async move {
            let result = api::fetch_logs(&token_value, &unit_list, &page, PAGE).await;
            if generation.get_value() != current {
                return;
            }
            loading.set(false);
            match result {
                Ok(response) => {
                    at_start.set(response.entries.len() < PAGE);
                    entries.set(newest_first(response.entries));
                }
                Err(message) => fail(message),
            }
        });
    };

    // A change of service, of date, or the first token starts the view over.
    Effect::new(move |_| {
        let _ = (token.get(), units.get(), until.get());
        reload();
    });

    // Fetch what is new since the newest row.
    let poll = move || {
        if paused.get_untracked()
            || until.get_untracked().is_some()
            || loading.get_untracked()
            || polling.get_value()
        {
            return;
        }
        let token_value = token.get_untracked();
        let unit_list = units.get_untracked();
        if token_value.is_empty() || unit_list.is_empty() {
            return;
        }
        let newest = entries.with_untracked(|rows| rows.first().map(|row| row.cursor.clone()));
        let page = newest.map_or(LogPage::Newest, LogPage::After);
        let current = generation.get_value();
        polling.set_value(true);
        spawn_local(async move {
            let result = api::fetch_logs(&token_value, &unit_list, &page, PAGE).await;
            polling.set_value(false);
            if generation.get_value() != current {
                return;
            }
            match result {
                Ok(response) => {
                    error.set(None);
                    cursor_reset.set(response.cursor_reset);
                    if response.cursor_reset {
                        at_start.set(false);
                        entries.set(newest_first(response.entries));
                    } else if !response.entries.is_empty() {
                        entries.update(|rows| {
                            if prepend_new(rows, response.entries) {
                                at_start.set(false);
                            }
                        });
                    }
                }
                Err(message) => fail(message),
            }
        });
    };

    // The Effect keeps the Interval alive while the viewer is shown.
    Effect::new(move |_prev: Option<Option<Interval>>| {
        if token.get().is_empty() {
            None
        } else {
            Some(Interval::new(POLL_MS, poll))
        }
    });

    // Fetch the page before the oldest row.
    let load_older = move || {
        if at_start.get_untracked() || loading.get_untracked() || loading_older.get_value() {
            return;
        }
        let Some(oldest) = entries.with_untracked(|rows| rows.last().map(|row| row.cursor.clone()))
        else {
            return;
        };
        let token_value = token.get_untracked();
        let unit_list = units.get_untracked();
        let current = generation.get_value();
        loading_older.set_value(true);
        spawn_local(async move {
            let result =
                api::fetch_logs(&token_value, &unit_list, &LogPage::Before(oldest), PAGE).await;
            loading_older.set_value(false);
            if generation.get_value() != current {
                return;
            }
            match result {
                Ok(response) => {
                    at_start.set(response.entries.len() < PAGE);
                    entries.update(|rows| rows.extend(newest_first(response.entries)));
                }
                Err(message) => fail(message),
            }
        });
    };

    let on_scroll = move |_| {
        if let Some(element) = scroll_ref.get_untracked() {
            let remaining =
                element.scroll_height() - element.scroll_top() - element.client_height();
            if remaining < LOAD_OLDER_MARGIN {
                load_older();
            }
        }
    };

    let go_to_latest = move |_| {
        date_input.set(String::new());
        until.set(None);
        if let Some(element) = scroll_ref.get_untracked() {
            element.set_scroll_top(0);
        }
    };

    let status = move || {
        if until.get().is_some() {
            ("bg-slate-500", "Viewing history")
        } else if paused.get() {
            ("bg-amber-400", "Paused")
        } else {
            ("bg-emerald-400 animate-pulse", "Live")
        }
    };

    let rows = move || {
        let query = filter.get();
        let mut previous_day = String::new();
        let mut out = Vec::new();
        for entry in entries.get() {
            let (day, time) = local_parts(entry.realtime_us);
            let shown_time = if full_time.get() {
                local_full(entry.realtime_us)
            } else {
                time.clone()
            };
            let source = short_unit(&entry.unit).to_string();
            let pid = entry.pid.map(|pid| format!("[{pid}]")).unwrap_or_default();
            let fields = [
                day.clone(),
                time.clone(),
                source.clone(),
                entry.identifier.clone(),
                priority_name(entry.priority).to_string(),
                entry.message.clone(),
            ];
            if !matches_filter(&query, &fields) {
                continue;
            }
            if day != previous_day {
                out.push(
                    view! {
                        <tr class="bg-slate-900/80">
                            <th colspan="3" scope="colgroup" class="px-3 py-1 text-left text-xs font-medium text-slate-400">{day.clone()}</th>
                        </tr>
                    }
                    .into_any(),
                );
                previous_day = day;
            }
            out.push(
                view! {
                    <tr class="align-top hover:bg-white/[0.03]" title=priority_name(entry.priority)>
                        <td class="pl-3 pr-2 py-0.5 whitespace-nowrap text-slate-500">{shown_time}</td>
                        <td class="px-2 py-0.5 whitespace-nowrap">
                            {show_unit.then(|| view! {
                                <span class=unit_class(&entry.unit)>{source}</span>
                            })}
                            <span class="text-slate-600">{pid}</span>
                        </td>
                        <td class=format!("pl-2 pr-3 py-0.5 whitespace-pre-wrap break-words w-full {}", priority_class(entry.priority))>
                            {entry.message.clone()}
                        </td>
                    </tr>
                }
                .into_any(),
            );
        }
        out
    };

    view! {
        <div class="space-y-3">
            <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center gap-2 text-sm text-slate-300 mr-2">
                    <span class=move || format!("w-2 h-2 rounded-full {}", status().0)></span>
                    {move || status().1}
                </span>
                <button
                    type="button"
                    class="px-3 py-1.5 bg-gray-600 hover:bg-gray-500 disabled:opacity-40 text-white rounded text-sm"
                    disabled=move || until.get().is_some()
                    on:click=move |_| paused.update(|value| *value = !*value)
                >
                    {move || if paused.get() { "Resume" } else { "Pause" }}
                </button>
                <label class="flex items-center gap-2 text-sm text-slate-400">
                    "Go to"
                    <input
                        type="datetime-local"
                        class="px-2 py-1 bg-gray-700 text-gray-200 rounded border border-gray-600 text-sm"
                        prop:value=move || date_input.get()
                        on:change=move |ev| {
                            let value = event_target_value(&ev);
                            date_input.set(value.clone());
                            until.set(parse_local_datetime(&value));
                        }
                    />
                </label>
                <button
                    type="button"
                    class="px-3 py-1.5 bg-sky-700 hover:bg-sky-600 disabled:opacity-40 text-white rounded text-sm"
                    disabled=move || until.get().is_none()
                    on:click=go_to_latest
                >
                    "Latest"
                </button>
                <label class="flex items-center gap-2 text-sm text-slate-400">
                    <input
                        type="checkbox"
                        prop:checked=move || full_time.get()
                        on:change=move |ev| full_time.set(event_target_checked(&ev))
                    />
                    "Full timestamps"
                </label>
                <div class="ml-auto">
                    <FilterBox query=filter placeholder="Filter loaded lines" />
                </div>
            </div>

            {move || cursor_reset.get().then(|| view! {
                <p class="text-gray-400 text-xs">
                    "The previous position in the journal is no longer available, so the most recent lines are shown."
                </p>
            })}
            {move || error.get().map(|message| view! {
                <p class="text-red-400 text-sm">"Could not read the log: "{message}</p>
            })}

            <div
                node_ref=scroll_ref
                on:scroll=on_scroll
                class="overflow-auto max-h-[70vh] min-h-48 border border-gray-700 rounded bg-slate-950"
            >
                <table class="min-w-full text-xs font-mono">
                    <tbody>{rows}</tbody>
                </table>
                {move || {
                    let empty = entries.with(|rows| rows.is_empty());
                    if loading.get() {
                        view! { <p class="p-3 text-sm text-slate-500">"Loading..."</p> }.into_any()
                    } else if units.with(|list| list.is_empty()) {
                        view! { <p class="p-3 text-sm text-slate-500">"Select at least one service."</p> }.into_any()
                    } else if empty {
                        view! { <p class="p-3 text-sm text-slate-500">"No log entries."</p> }.into_any()
                    } else if at_start.get() {
                        view! { <p class="p-3 text-xs text-slate-600 text-center">"Start of the journal for these services"</p> }.into_any()
                    } else {
                        view! {
                            <div class="p-2 text-center">
                                <button
                                    type="button"
                                    class="px-3 py-1 text-xs text-slate-300 hover:text-white bg-white/5 rounded"
                                    on:click=move |_| load_older()
                                >
                                    "Load older entries"
                                </button>
                            </div>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cursor: &str) -> JournalEntry {
        JournalEntry {
            cursor: cursor.to_string(),
            realtime_us: 0,
            unit: "dnsmasq.service".to_string(),
            identifier: "dnsmasq".to_string(),
            pid: None,
            priority: 6,
            message: String::new(),
        }
    }

    fn cursors(rows: &[JournalEntry]) -> Vec<&str> {
        rows.iter().map(|row| row.cursor.as_str()).collect()
    }

    #[test]
    fn new_entries_go_in_front_with_the_newest_first() {
        let mut rows = vec![entry("b"), entry("a")];
        prepend_new(&mut rows, vec![entry("c"), entry("d")]);
        assert_eq!(cursors(&rows), ["d", "c", "b", "a"]);
    }

    #[test]
    fn the_row_cap_drops_the_oldest_rows() {
        let mut rows: Vec<_> = (0..MAX_ROWS).map(|n| entry(&format!("old{n}"))).collect();
        let dropped = prepend_new(&mut rows, vec![entry("new")]);
        assert!(dropped);
        assert_eq!(rows.len(), MAX_ROWS);
        assert_eq!(rows[0].cursor, "new");
        assert_eq!(rows[1].cursor, "old0");
        assert!(!prepend_new(&mut rows[..1].to_vec(), Vec::new()));
    }

    #[test]
    fn every_severity_has_a_colour_and_a_name() {
        for priority in 0..=7 {
            assert!(priority_class(priority).starts_with("text-"));
            assert!(!priority_name(priority).is_empty());
        }
        assert_ne!(priority_class(3), priority_class(6));
    }

    #[test]
    fn a_service_keeps_its_colour() {
        assert_eq!(short_unit("dnsmasq.service"), "dnsmasq");
        assert_eq!(short_unit("odd"), "odd");
        assert_eq!(unit_class("dnsmasq.service"), unit_class("dnsmasq.service"));
    }
}
