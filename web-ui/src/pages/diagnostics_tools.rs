//! Diagnostics: ping, traceroute, DNS lookup and TCP port check from the router.

use crate::api;
use crate::components::form_utils::event_target_value;
use keystone_core::diagnostics::{
    DiagnosticRequest, DiagnosticResponse, DnsRecordType, IpFamily, PING_MAX_COUNT,
    TRACEROUTE_MAX_HOPS,
};
use leptos::prelude::*;
use leptos::task::spawn_local;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tool {
    Ping,
    Traceroute,
    Dns,
    Tcp,
}

impl Tool {
    const ALL: [Tool; 4] = [Tool::Ping, Tool::Traceroute, Tool::Dns, Tool::Tcp];

    fn label(self) -> &'static str {
        match self {
            Tool::Ping => "Ping",
            Tool::Traceroute => "Traceroute",
            Tool::Dns => "DNS lookup",
            Tool::Tcp => "TCP port",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Tool::Ping => "Send ICMP echo requests from the router.",
            Tool::Traceroute => "Show the path packets take to a host, hop by hop.",
            Tool::Dns => "Ask a resolver for a record. An IP address is looked up in reverse.",
            Tool::Tcp => "Check whether a TCP port accepts connections.",
        }
    }
}

/// The values of every form field. Fields a tool does not use are ignored.
#[derive(Clone, Debug, Default)]
struct Form {
    host: String,
    count: String,
    max_hops: String,
    family: String,
    interface: String,
    record_type: String,
    server: String,
    port: String,
}

fn parse_number<T: std::str::FromStr>(text: &str, field: &str) -> Result<T, String> {
    text.trim()
        .parse()
        .map_err(|_| format!("{field} must be a number"))
}

fn parse_family(value: &str) -> IpFamily {
    match value {
        "v4" => IpFamily::V4,
        "v6" => IpFamily::V6,
        _ => IpFamily::Any,
    }
}

fn parse_record_type(value: &str) -> DnsRecordType {
    DnsRecordType::ALL
        .into_iter()
        .find(|record| record.as_str() == value)
        .unwrap_or_default()
}

fn optional(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Build the request for `tool` and check it the way the daemon will.
fn build_request(tool: Tool, form: &Form) -> Result<DiagnosticRequest, String> {
    let host = form.host.trim().to_string();
    let request = match tool {
        Tool::Ping => DiagnosticRequest::Ping {
            host,
            count: parse_number(&form.count, "Count")?,
            family: parse_family(&form.family),
            interface: optional(&form.interface),
        },
        Tool::Traceroute => DiagnosticRequest::Traceroute {
            host,
            max_hops: parse_number(&form.max_hops, "Maximum hops")?,
            family: parse_family(&form.family),
        },
        Tool::Dns => DiagnosticRequest::DnsLookup {
            name: host,
            record_type: parse_record_type(&form.record_type),
            server: optional(&form.server),
        },
        Tool::Tcp => DiagnosticRequest::TcpConnect {
            host,
            port: parse_number(&form.port, "Port")?,
        },
    };
    request.validate()?;
    Ok(request)
}

fn initial_form() -> Form {
    Form {
        count: "4".into(),
        max_hops: "20".into(),
        record_type: "A".into(),
        ..Form::default()
    }
}

/// One-line summary above the output.
fn summary(response: &DiagnosticResponse) -> String {
    let seconds = response.duration_ms as f64 / 1000.0;
    if response.timed_out {
        format!("Timed out after {seconds:.1} s")
    } else if response.success {
        format!("Completed in {seconds:.1} s")
    } else {
        match response.exit_code {
            Some(code) => format!("Failed (exit status {code}) after {seconds:.1} s"),
            None => format!("Failed after {seconds:.1} s"),
        }
    }
}

#[component]
pub fn DiagnosticsToolsPage(
    auth_token: ReadSignal<Option<String>>,
    on_unauthorized: Callback<()>,
) -> impl IntoView {
    let token = Signal::derive(move || auth_token.get().unwrap_or_default());
    let tool = RwSignal::new(Tool::Ping);
    let form = RwSignal::new(initial_form());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    let result = RwSignal::new(None::<DiagnosticResponse>);
    let interfaces = RwSignal::new(Vec::<String>::new());

    Effect::new(move |_| {
        let token_value = token.get();
        if token_value.is_empty() {
            return;
        }
        spawn_local(async move {
            if let Ok(state) = api::fetch_system_state(&token_value).await {
                interfaces.set(state.interfaces.into_iter().map(|i| i.name).collect());
            }
        });
    });

    let set = move |update: fn(&mut Form, String)| {
        move |ev: leptos::ev::Event| form.update(|f| update(f, event_target_value(&ev)))
    };

    let submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let request = match build_request(tool.get_untracked(), &form.get_untracked()) {
            Ok(request) => request,
            Err(message) => {
                error.set(Some(message));
                return;
            }
        };
        error.set(None);
        busy.set(true);
        let token_value = token.get_untracked();
        spawn_local(async move {
            match api::run_diagnostic(&token_value, &request).await {
                Ok(response) => result.set(Some(response)),
                Err(message) if message.contains("Unauthorized") => on_unauthorized.run(()),
                Err(message) => error.set(Some(message)),
            }
            busy.set(false);
        });
    };

    let input_class =
        "px-2 py-1.5 bg-gray-700 text-gray-200 rounded border border-gray-600 text-sm w-full";

    view! {
        <div class="space-y-4">
            <div>
                <h1 class="text-2xl font-semibold text-blue-300">"Network tools"</h1>
                <p class="text-gray-400 text-sm">"Run connectivity checks from the router itself."</p>
            </div>

            <div class="flex flex-wrap gap-1 border-b border-gray-700" role="tablist">
                {Tool::ALL
                    .into_iter()
                    .map(|candidate| {
                        view! {
                            <button
                                type="button"
                                role="tab"
                                aria-selected=move || tool.get() == candidate
                                class=move || if tool.get() == candidate {
                                    "px-4 py-2 text-sm border-b-2 border-blue-400 text-blue-300"
                                } else {
                                    "px-4 py-2 text-sm border-b-2 border-transparent text-gray-400 hover:text-gray-200"
                                }
                                on:click=move |_| {
                                    tool.set(candidate);
                                    error.set(None);
                                    result.set(None);
                                }
                            >
                                {candidate.label()}
                            </button>
                        }
                    })
                    .collect_view()}
            </div>

            <p class="text-gray-500 text-xs">{move || tool.get().hint()}</p>

            <form class="grid grid-cols-1 md:grid-cols-2 gap-4" on:submit=submit>
                <label class="space-y-1 md:col-span-2">
                    <span class="text-sm text-gray-300">
                        {move || match tool.get() {
                            Tool::Dns => "Name or IP address",
                            _ => "Host name or IP address",
                        }}
                    </span>
                    <input
                        class=input_class
                        placeholder="example.com"
                        autocomplete="off"
                        autocapitalize="off"
                        spellcheck="false"
                        prop:value=move || form.with(|f| f.host.clone())
                        on:input=set(|f, v| f.host = v)
                    />
                </label>

                <Show when=move || tool.get() == Tool::Ping>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">{format!("Count (1-{PING_MAX_COUNT})")}</span>
                        <input class=input_class inputmode="numeric"
                            prop:value=move || form.with(|f| f.count.clone())
                            on:input=set(|f, v| f.count = v) />
                    </label>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Send from interface"</span>
                        <select class=input_class
                            prop:value=move || form.with(|f| f.interface.clone())
                            on:change=set(|f, v| f.interface = v)>
                            <option value="">"Routing table decides"</option>
                            {move || interfaces
                                .get()
                                .into_iter()
                                .map(|name| { let label = name.clone(); view! { <option value=name>{label}</option> } })
                                .collect_view()}
                        </select>
                    </label>
                </Show>

                <Show when=move || tool.get() == Tool::Traceroute>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">{format!("Maximum hops (1-{TRACEROUTE_MAX_HOPS})")}</span>
                        <input class=input_class inputmode="numeric"
                            prop:value=move || form.with(|f| f.max_hops.clone())
                            on:input=set(|f, v| f.max_hops = v) />
                    </label>
                </Show>

                <Show when=move || matches!(tool.get(), Tool::Ping | Tool::Traceroute)>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"IP version"</span>
                        <select class=input_class
                            prop:value=move || form.with(|f| f.family.clone())
                            on:change=set(|f, v| f.family = v)>
                            <option value="">"Automatic"</option>
                            <option value="v4">"IPv4"</option>
                            <option value="v6">"IPv6"</option>
                        </select>
                    </label>
                </Show>

                <Show when=move || tool.get() == Tool::Dns>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Record type"</span>
                        <select class=input_class
                            prop:value=move || form.with(|f| f.record_type.clone())
                            on:change=set(|f, v| f.record_type = v)>
                            {DnsRecordType::ALL
                                .into_iter()
                                .map(|record| view! { <option value=record.as_str()>{record.as_str()}</option> })
                                .collect_view()}
                        </select>
                    </label>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Resolver (optional)"</span>
                        <input class=input_class placeholder="1.1.1.1, default: the router's resolver"
                            autocomplete="off" spellcheck="false"
                            prop:value=move || form.with(|f| f.server.clone())
                            on:input=set(|f, v| f.server = v) />
                    </label>
                </Show>

                <Show when=move || tool.get() == Tool::Tcp>
                    <label class="space-y-1">
                        <span class="text-sm text-gray-300">"Port"</span>
                        <input class=input_class inputmode="numeric" placeholder="443"
                            prop:value=move || form.with(|f| f.port.clone())
                            on:input=set(|f, v| f.port = v) />
                    </label>
                </Show>

                <div class="md:col-span-2 flex items-center gap-4">
                    <button type="submit"
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded text-sm"
                        disabled=move || busy.get()>
                        {move || if busy.get() { "Running..." } else { "Run" }}
                    </button>
                    {move || error.get().map(|message| view! {
                        <span class="text-red-400 text-sm">{message}</span>
                    })}
                </div>
            </form>

            {move || result.get().map(|response| {
                let status_class = if response.success {
                    "text-emerald-400"
                } else {
                    "text-red-400"
                };
                view! {
                    <div class="space-y-2">
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-sm">
                            <span class=status_class>{summary(&response)}</span>
                            <code class="text-gray-500 text-xs break-all">{response.command.clone()}</code>
                        </div>
                        <pre class="bg-gray-900 border border-gray-700 rounded p-3 text-xs text-gray-200 font-mono overflow-x-auto whitespace-pre-wrap break-all max-h-[32rem] overflow-y-auto">
                            {response.output.clone()}
                        </pre>
                        {response.truncated.then(|| view! {
                            <p class="text-yellow-500 text-xs">"Output was cut to its size limit."</p>
                        })}
                    </div>
                }
            })}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(host: &str) -> Form {
        Form {
            host: host.into(),
            ..initial_form()
        }
    }

    #[test]
    fn each_tool_builds_its_request_from_the_form() {
        let ping = build_request(Tool::Ping, &form(" example.com ")).unwrap();
        assert_eq!(
            ping,
            DiagnosticRequest::Ping {
                host: "example.com".into(),
                count: 4,
                family: IpFamily::Any,
                interface: None,
            }
        );
        let mut dns = form("example.com");
        dns.record_type = "MX".into();
        dns.server = " 1.1.1.1 ".into();
        assert_eq!(
            build_request(Tool::Dns, &dns).unwrap(),
            DiagnosticRequest::DnsLookup {
                name: "example.com".into(),
                record_type: DnsRecordType::MX,
                server: Some("1.1.1.1".into()),
            }
        );
        let mut tcp = form("example.com");
        tcp.port = "443".into();
        assert!(build_request(Tool::Tcp, &tcp).is_ok());
    }

    #[test]
    fn bad_input_is_reported_before_anything_is_sent() {
        assert!(build_request(Tool::Ping, &form("")).is_err());
        assert!(build_request(Tool::Ping, &form("-f")).is_err());
        let mut tcp = form("example.com");
        assert!(build_request(Tool::Tcp, &tcp).unwrap_err().contains("Port"));
        tcp.port = "70000".into();
        assert!(build_request(Tool::Tcp, &tcp).is_err());
        let mut hops = form("example.com");
        hops.max_hops = "99".into();
        assert!(build_request(Tool::Traceroute, &hops).is_err());
    }

    #[test]
    fn every_dns_record_type_is_selectable() {
        for record in DnsRecordType::ALL {
            assert_eq!(parse_record_type(record.as_str()), record);
        }
    }

    #[test]
    fn the_summary_distinguishes_success_timeout_and_failure() {
        let base = DiagnosticResponse {
            duration_ms: 1500,
            ..Default::default()
        };
        assert!(summary(&base).starts_with("Failed after"));
        assert!(
            summary(&DiagnosticResponse {
                success: true,
                ..base.clone()
            })
            .starts_with("Completed")
        );
        assert!(
            summary(&DiagnosticResponse {
                timed_out: true,
                ..base.clone()
            })
            .starts_with("Timed out")
        );
        assert!(
            summary(&DiagnosticResponse {
                exit_code: Some(2),
                ..base
            })
            .contains("exit status 2")
        );
    }
}
