// checks packet expectations against parsed trace information

use super::trace::TraceInfo;
use crate::config::{Verdict, same_address};
use anyhow::Result;

/// validate expectations using trace information only.
/// returns None when every expectation holds, or the reason the first one failed.
pub(super) fn validate_expectations_from_trace(
    step: &crate::config::PacketStep,
    trace_info: Option<&TraceInfo>,
    verbose: bool,
) -> Result<Option<String>> {
    // print a failure in verbose mode and hand back its reason
    let fail = |reason: String| -> Result<Option<String>> {
        if verbose {
            println!("    x {}", reason);
        }
        Ok(Some(reason))
    };

    if step.expect.is_empty() {
        return Ok(None);
    }

    let Some(trace_info) = trace_info else {
        if verbose {
            println!("    x packet not found in trace");
            println!("       possible causes:");
            println!(
                "       - packet dropped before netfilter hooks (malformed, kernel validation failure)"
            );
            println!(
                "       - IPv6 link-local addresses may require proper interface configuration"
            );
            println!(
                "       - loopback traffic (127.0.0.1) won't route through physical interfaces"
            );
            println!("       - OUTPUT hook tests need packets generated from inside the guest");
        }
        return Ok(Some("packet not found in trace".to_string()));
    };

    for expectation in &step.expect {
        // an expected output interface implies forwarding; otherwise assume local delivery
        let inferred_hook = if let Some(ref hook) = expectation.hook {
            hook.to_uppercase()
        } else if expectation.to_interface.is_some() {
            "FORWARD".to_string()
        } else {
            "INPUT".to_string()
        };

        let hook_verdict = trace_info.hook_verdicts.get(&inferred_hook);

        if hook_verdict.is_none() {
            return fail(format!(
                "packet did not pass through {} hook. hooks traversed: {:?}",
                inferred_hook,
                trace_info.hook_verdicts.keys().collect::<Vec<_>>()
            ));
        }

        let actual_verdict = hook_verdict.unwrap();
        let expected_verdict_str = format!("{:?}", expectation.verdict).to_lowercase();

        let verdict_matches = match expectation.verdict {
            Verdict::Drop => actual_verdict == "drop",
            Verdict::Accept => actual_verdict == "accept",
            Verdict::Reject => actual_verdict == "reject",
        };

        let all_hooks: Vec<String> = trace_info.hook_verdicts.keys().cloned().collect();
        let hook_info = format!(
            " at {} hook (packet traversed: {:?})",
            inferred_hook, all_hooks
        );

        if !verdict_matches {
            return fail(format!(
                "verdict: {} (expected {}){}",
                actual_verdict, expected_verdict_str, hook_info
            ));
        }
        if verbose {
            println!("    ok verdict: {}{}", actual_verdict, hook_info);
        }

        if let Some(ref to_iface) = expectation.to_interface {
            let iface_matches = trace_info
                .oif
                .as_ref()
                .map(|oif| oif == to_iface)
                .unwrap_or(false);

            if !iface_matches {
                return fail(match trace_info.oif {
                    Some(ref actual_oif) => format!(
                        "expected forwarding to {}, but trace shows oif: {}",
                        to_iface, actual_oif
                    ),
                    None => format!(
                        "expected forwarding to {}, but no oif in trace (packet not forwarded)",
                        to_iface
                    ),
                });
            }
            if verbose {
                println!("    ok forwarded to interface: {}", to_iface);
            }
        }

        if let Some(ref expected_src_nat) = expectation.src_nat {
            let actual_nat = trace_info.src_nat.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "expected SNAT to {}, but no SNAT detected in trace",
                    expected_src_nat
                )
            })?;

            if !same_address(actual_nat, expected_src_nat) {
                return fail(format!("SNAT: expected {}, got {}", expected_src_nat, actual_nat));
            }
            if verbose {
                println!("    ok SNAT: {}", expected_src_nat);
            }
        }

        if let Some(ref expected_dst_nat) = expectation.dst_nat {
            let actual_nat = trace_info.dst_nat.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "expected DNAT to {}, but no DNAT detected in trace",
                    expected_dst_nat
                )
            })?;

            if !same_address(actual_nat, expected_dst_nat) {
                return fail(format!("DNAT: expected {}, got {}", expected_dst_nat, actual_nat));
            }
            if verbose {
                println!("    ok DNAT: {}", expected_dst_nat);
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn step(expect: &str) -> crate::config::PacketStep {
        toml::from_str(&format!(
            "packet = {{ on_interface = \"eth0\", source_ip = \"192.0.2.1\", dest_ip = \"192.0.2.2\", tcp = {{ source_port = 1000, dest_port = 22 }} }}\nexpect = [ {} ]",
            expect
        ))
        .unwrap()
    }

    fn trace(hook: &str, verdict: &str) -> TraceInfo {
        TraceInfo {
            hook_verdicts: HashMap::from([(hook.to_string(), verdict.to_string())]),
            oif: None,
            src_nat: None,
            dst_nat: None,
            masquerade: false,
        }
    }

    #[test]
    fn matching_expectation_has_no_failure() {
        let step = step("{ hook = \"input\", verdict = \"accept\" }");
        assert_eq!(validate_expectations_from_trace(&step, Some(&trace("INPUT", "accept")), false).unwrap(), None);
    }

    #[test]
    fn wrong_verdict_says_what_happened() {
        let step = step("{ hook = \"input\", verdict = \"reject\" }");
        let reason = validate_expectations_from_trace(&step, Some(&trace("INPUT", "accept")), false)
            .unwrap()
            .expect("expected a failure");
        assert!(reason.contains("accept") && reason.contains("expected reject"), "{}", reason);
    }

    #[test]
    fn missing_packet_is_a_failure() {
        let step = step("{ hook = \"input\", verdict = \"accept\" }");
        let reason = validate_expectations_from_trace(&step, None, false).unwrap();
        assert!(reason.unwrap().contains("not found in trace"));
    }
}
