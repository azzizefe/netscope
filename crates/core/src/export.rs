use crate::stats::StatsSnapshot;

pub fn export_llm_json(snapshot: &StatsSnapshot) -> String {
    let llm = &snapshot.llm;
    let mut parts = Vec::new();

    parts.push(format!(
        r#""total_requests":{},"total_tokens":{},"total_cost":{:.6},"session_cost":{:.6},"daily_cost":{:.6}"#,
        llm.total_requests, llm.total_tokens, llm.total_cost, llm.session_cost, llm.daily_cost
    ));

    let models: Vec<String> = llm
        .per_model
        .iter()
        .map(|(model, ms)| {
            let avg_ttft = if ms.ttft_count > 0 {
                ms.ttft_sum_ms as f64 / ms.ttft_count as f64
            } else {
                0.0
            };
            let avg_tpot = if ms.tpot_count > 0 {
                ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0
            } else {
                0.0
            };
            let avg_tps = if ms.tokens_per_second_count > 0 {
                ms.tokens_per_second_sum / ms.tokens_per_second_count as f64
            } else {
                0.0
            };
            let error_rate = if ms.requests > 0 {
                (ms.error_4xx + ms.error_5xx) as f64 / ms.requests as f64 * 100.0
            } else {
                0.0
            };
            let rl_rate = if ms.requests > 0 {
                ms.rate_limited as f64 / ms.requests as f64 * 100.0
            } else {
                0.0
            };
            let kesinti = if ms.total_streams > 0 {
                ms.incomplete_streams as f64 / ms.total_streams as f64 * 100.0
            } else {
                0.0
            };
            format!(
                r#"{{"model":"{}","requests":{},"prompt_tokens":{},"completion_tokens":{},"total_tokens":{},"cost":{:.6},"avg_ttft_ms":{:.1},"avg_tpot_ms":{:.1},"avg_tokens_per_second":{:.1},"error_4xx":{},"error_5xx":{},"rate_limited":{},"incomplete_streams":{},"total_streams":{},"error_rate_pct":{:.1},"rate_limit_pct":{:.1},"kesintisi_pct":{:.1}}}"#,
                model,
                ms.requests,
                ms.prompt_tokens,
                ms.completion_tokens,
                ms.total_tokens,
                ms.cost,
                avg_ttft,
                avg_tpot,
                avg_tps,
                ms.error_4xx,
                ms.error_5xx,
                ms.rate_limited,
                ms.incomplete_streams,
                ms.total_streams,
                error_rate,
                rl_rate,
                kesinti,
            )
        })
        .collect();

    let providers: Vec<String> = llm
        .per_provider
        .iter()
        .map(|(prov, ps)| {
            format!(
                r#"{{"provider":"{}","requests":{},"tokens":{},"cost":{:.6},"errors":{}}}"#,
                prov, ps.requests, ps.total_tokens, ps.cost, ps.errors
            )
        })
        .collect();

    let anomalies: Vec<String> = llm
        .anomalies
        .iter()
        .map(|a| {
            format!(
                r#"{{"model":"{}","metric":"{}","value":"{}","threshold":"{}","timestamp":"{}"}}"#,
                a.model, a.metric, a.value, a.threshold, a.timestamp
            )
        })
        .collect();

    let heatmap_points = llm
        .latency_heatmap
        .iter()
        .map(|(ts, model, ttft)| format!(r#"["{}","{}",{}]"#, ts, model, ttft))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{{},\"model_stats\":[{}],\"provider_stats\":[{}],\"anomalies\":[{}],\"heatmap\":[{}]}}",
        parts.join(","),
        models.join(","),
        providers.join(","),
        anomalies.join(","),
        heatmap_points,
    )
}

pub fn export_llm_otlp(snapshot: &StatsSnapshot) -> String {
    let llm = &snapshot.llm;
    let now_ms = chrono::Utc::now().timestamp_millis();

    let mut metrics = Vec::new();

    for (model, ms) in &llm.per_model {
        let avg_ttft = if ms.ttft_count > 0 {
            ms.ttft_sum_ms as f64 / ms.ttft_count as f64
        } else {
            0.0
        };
        let avg_tpot = if ms.tpot_count > 0 {
            ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0
        } else {
            0.0
        };

        metrics.push(format!(
            r#"{{"resourceMetrics":[{{"resource":{{"attributes":[{{"key":"service.name","value":{{"stringValue":"netscope"}}}},{{"key":"llm.model","value":{{"stringValue":"{}"}}}}]}},"scopeMetrics":[{{"scope":{{"name":"netscope.llm"}},"metrics":[
{{"name":"llm.ttft","description":"Time to first token","unit":"ms","gauge":{{"dataPoints":[{{"timeUnixNano":{},"asDouble":{}}}]}}}},
{{"name":"llm.tpot","description":"Time per output token","unit":"ms","gauge":{{"dataPoints":[{{"timeUnixNano":{},"asDouble":{}}}]}}}},
{{"name":"llm.requests","description":"Total requests","unit":"1","sum":{{"dataPoints":[{{"timeUnixNano":{},"asInt":"{}"}}],"isMonotonic":true}}}},
{{"name":"llm.tokens","description":"Total tokens","unit":"1","sum":{{"dataPoints":[{{"timeUnixNano":{},"asInt":"{}"}}],"isMonotonic":true}}}},
{{"name":"llm.cost","description":"Total cost USD","unit":"1","sum":{{"dataPoints":[{{"timeUnixNano":{},"asDouble":{}}}]}}}},
{{"name":"llm.errors","description":"Total errors","unit":"1","sum":{{"dataPoints":[{{"timeUnixNano":{},"asInt":"{}"}}],"isMonotonic":true}}}}
]}}]}}]}}"#,
            model,
            now_ms, avg_ttft,
            now_ms, avg_tpot,
            now_ms, ms.requests,
            now_ms, ms.total_tokens,
            now_ms, ms.cost,
            now_ms, ms.errors,
        ));
    }

    format!("[{}]", metrics.join(","))
}

pub fn export_llm_prometheus(snapshot: &StatsSnapshot) -> String {
    let llm = &snapshot.llm;
    let mut lines = Vec::new();

    lines.push("# HELP llm_total_requests Total LLM requests".into());
    lines.push(format!("llm_total_requests {}", llm.total_requests));
    lines.push("# HELP llm_total_cost Total cost USD".into());
    lines.push(format!("llm_total_cost {}", llm.total_cost));
    lines.push("# HELP llm_total_tokens Total tokens".into());
    lines.push(format!("llm_total_tokens {}", llm.total_tokens));
    lines.push("# HELP llm_session_cost Current session cost".into());
    lines.push(format!("llm_session_cost {}", llm.session_cost));
    lines.push("# HELP llm_daily_cost Daily cost".into());
    lines.push(format!("llm_daily_cost {}", llm.daily_cost));

    for (model, ms) in &llm.per_model {
        let _safe = model.replace(['"', '-'], "_");
        let avg_ttft = if ms.ttft_count > 0 {
            ms.ttft_sum_ms as f64 / ms.ttft_count as f64
        } else {
            0.0
        };
        let avg_tpot = if ms.tpot_count > 0 {
            ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0
        } else {
            0.0
        };
        let avg_tps = if ms.tokens_per_second_count > 0 {
            ms.tokens_per_second_sum / ms.tokens_per_second_count as f64
        } else {
            0.0
        };

        let labels = format!("model=\"{}\"", model);
        lines.push(format!("llm_requests{{{}}} {}", labels, ms.requests));
        lines.push(format!(
            "llm_tokens_total{{{}}} {}",
            labels, ms.total_tokens
        ));
        lines.push(format!("llm_cost_total{{{}}} {}", labels, ms.cost));
        lines.push(format!("llm_avg_ttft_ms{{{}}} {:.1}", labels, avg_ttft));
        lines.push(format!("llm_avg_tpot_ms{{{}}} {:.1}", labels, avg_tpot));
        lines.push(format!(
            "llm_avg_tokens_per_second{{{}}} {:.1}",
            labels, avg_tps
        ));
        lines.push(format!("llm_errors{{{}}} {}", labels, ms.errors));
        lines.push(format!("llm_error_4xx{{{}}} {}", labels, ms.error_4xx));
        lines.push(format!("llm_error_5xx{{{}}} {}", labels, ms.error_5xx));
        lines.push(format!(
            "llm_rate_limited{{{}}} {}",
            labels, ms.rate_limited
        ));
        lines.push(format!(
            "llm_incomplete_streams{{{}}} {}",
            labels, ms.incomplete_streams
        ));
        lines.push(format!(
            "llm_total_streams{{{}}} {}",
            labels, ms.total_streams
        ));
    }

    lines.push("# EOF".to_string());
    lines.join("\n")
}
