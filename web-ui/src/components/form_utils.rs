//! Shared form utilities for interface configuration

use leptos::prelude::*;

/// Extract checked state from a checkbox event
pub fn event_target_checked(ev: &web_sys::Event) -> bool {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.checked())
        .unwrap_or(false)
}

/// Extract value from an input event
pub fn event_target_value(ev: &web_sys::Event) -> String {
    use wasm_bindgen::JsCast;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|e| e.value())
        .unwrap_or_default()
}

/// Multi-search selector component for selecting multiple items from a list
/// 
/// Features:
/// - Search/filter available items
/// - Add items by clicking or typing
/// - Remove items with × button
/// - Displays selected items as tags
#[component]
pub fn MultiSearchSelector(
    /// List of all available options
    available_items: Signal<Vec<String>>,
    /// Currently selected items (reactive)
    selected_items: RwSignal<Vec<String>>,
    /// Placeholder text for the search input
    #[prop(optional)]
    placeholder: &'static str,
    /// Label for the component
    #[prop(optional)]
    label: Option<&'static str>,
) -> impl IntoView {
    let search_query = RwSignal::new(String::new());
    let show_dropdown = RwSignal::new(false);

    // Filtered items based on search query, excluding already selected items
    let filtered_items = Signal::derive(move || {
        let query = search_query.get().to_lowercase();
        let selected = selected_items.get();
        
        available_items.get()
            .into_iter()
            .filter(|item| {
                // Exclude already selected items
                !selected.contains(item) &&
                // Filter by search query
                (query.is_empty() || item.to_lowercase().contains(&query))
            })
            .collect::<Vec<_>>()
    });

    // Add item to selection
    let add_item = move |item: String| {
        selected_items.update(|items| {
            if !items.contains(&item) {
                items.push(item);
            }
        });
        search_query.set(String::new());
        show_dropdown.set(false);
    };

    // Remove item from selection
    let remove_item = move |item: String| {
        selected_items.update(|items| {
            items.retain(|i| i != &item);
        });
    };

    view! {
        <div class="space-y-2">
            {label.map(|l| view! {
                <label class="block text-sm text-gray-400 mb-1">{l}</label>
            })}
            
            // Selected items as tags
            <div class="flex flex-wrap gap-2 mb-2">
                <For
                    each=move || selected_items.get()
                    key=|item| item.clone()
                    children=move |item: String| {
                        let item_for_remove = item.clone();
                        view! {
                            <span class="inline-flex items-center gap-1 px-2 py-1 bg-blue-600 text-white text-sm rounded">
                                {item.clone()}
                                <button
                                    type="button"
                                    class="hover:text-red-300 font-bold"
                                    on:click=move |_| remove_item(item_for_remove.clone())
                                >
                                    "×"
                                </button>
                            </span>
                        }
                    }
                />
            </div>

            // Search input
            <div class="relative">
                <input
                    type="text"
                    class="w-full px-3 py-2 bg-gray-600 text-gray-200 rounded border border-gray-500 focus:border-blue-500 focus:outline-none"
                    placeholder={placeholder}
                    prop:value=move || search_query.get()
                    on:input=move |ev| {
                        search_query.set(event_target_value(&ev));
                        show_dropdown.set(true);
                    }
                    on:focus=move |_| show_dropdown.set(true)
                    on:blur=move |_| {
                        // Delay hiding dropdown to allow click events to fire
                        let handle = leptos::prelude::set_timeout(
                            move || show_dropdown.set(false),
                            std::time::Duration::from_millis(200)
                        );
                        // Keep handle alive
                        let _ = handle;
                    }
                />

                // Dropdown with filtered items
                {move || {
                    if show_dropdown.get() && !filtered_items.get().is_empty() {
                        view! {
                            <div class="absolute z-10 w-full mt-1 bg-gray-700 border border-gray-600 rounded shadow-lg max-h-48 overflow-y-auto">
                                <For
                                    each=move || filtered_items.get()
                                    key=|item| item.clone()
                                    children=move |item: String| {
                                        let item_for_add = item.clone();
                                        view! {
                                            <button
                                                type="button"
                                                class="w-full text-left px-3 py-2 hover:bg-gray-600 text-gray-200 text-sm"
                                                on:click=move |_| add_item(item_for_add.clone())
                                            >
                                                {item}
                                            </button>
                                        }
                                    }
                                />
                            </div>
                        }.into_any()
                    } else {
                        view! { <div></div> }.into_any()
                    }
                }}
            </div>
        </div>
    }
}
