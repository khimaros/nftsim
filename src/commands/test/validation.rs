// src/commands/test/validation.rs
//
// Expectation validation functions for nftsim
// Validates packet expectations against trace information

use super::trace::TraceInfo;
use crate::config::Verdict;
use anyhow::Result;

/// Validate expectations using trace information only
pub(super) fn validate_expectations_from_trace(
    step: &crate::config::PacketStep,
    trace_info: Option<&TraceInfo>,
    verbose: bool,
) -> Result<bool> {
    if step.expect.is_empty() {
        // No expectations, always pass
        return Ok(true);
    }

    // If we don't have trace info, the packet wasn't found - this is a failure
    let Some(trace_info) = trace_info else {
        if verbose {
            println!("    ✗ Packet not found in trace");
            println!("       Possible causes:");
            println!(
                "       - Packet dropped before netfilter hooks (malformed, kernel validation failure)"
            );
            println!(
                "       - IPv6 link-local addresses may require proper interface configuration"
            );
            println!(
                "       - Loopback traffic (127.0.0.1) won't route through physical interfaces"
            );
            println!("       - OUTPUT hook tests need packets generated from inside the guest");
        }
        return Ok(false);
    };

    for expectation in &step.expect {
        // Infer hook if not specified
        let inferred_hook = if let Some(ref hook) = expectation.hook {
            hook.to_uppercase()
        } else if expectation.to_interface.is_some() {
            "FORWARD".to_string()
        } else {
            "INPUT".to_string() // Default assumption
        };

        // Check if packet passed through the expected hook
        let hook_verdict = trace_info.hook_verdicts.get(&inferred_hook);

        if hook_verdict.is_none() {
            if verbose {
                println!(
                    "    ✗ Packet did not pass through {} hook. Hooks traversed: {:?}",
                    inferred_hook,
                    trace_info.hook_verdicts.keys().collect::<Vec<_>>()
                );
            }
            return Ok(false);
        }

        // Check verdict at the specific hook
        let actual_verdict = hook_verdict.unwrap();
        let expected_verdict_str = format!("{:?}", expectation.verdict).to_lowercase();

        let verdict_matches = match expectation.verdict {
            Verdict::Drop => actual_verdict == "drop",
            Verdict::Accept => actual_verdict == "accept",
            Verdict::Reject => actual_verdict == "reject",
        };

        // Print verdict validation result
        if verbose {
            let all_hooks: Vec<String> = trace_info.hook_verdicts.keys().cloned().collect();
            let hook_info = format!(
                " at {} hook (packet traversed: {:?})",
                inferred_hook, all_hooks
            );

            if verdict_matches {
                println!("    ✓ Verdict: {}{}", actual_verdict, hook_info);
            } else {
                println!(
                    "    ✗ Verdict: {} (expected {}){}",
                    actual_verdict, expected_verdict_str, hook_info
                );
            }
        }

        if !verdict_matches {
            return Ok(false);
        }

        // Check interface forwarding using oif from trace
        if let Some(ref to_iface) = expectation.to_interface {
            let iface_matches = trace_info
                .oif
                .as_ref()
                .map(|oif| oif == to_iface)
                .unwrap_or(false);

            if verbose {
                if iface_matches {
                    println!("    ✓ Forwarded to interface: {}", to_iface);
                } else {
                    if let Some(ref actual_oif) = trace_info.oif {
                        println!(
                            "    ✗ Expected forwarding to {}, but trace shows oif: {}",
                            to_iface, actual_oif
                        );
                    } else {
                        println!(
                            "    ✗ Expected forwarding to {}, but no oif in trace (packet not forwarded)",
                            to_iface
                        );
                    }
                }
            }

            if !iface_matches {
                return Ok(false);
            }
        }

        // Check SNAT
        if let Some(ref expected_src_nat) = expectation.src_nat {
            let actual_nat = trace_info.src_nat.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Expected SNAT to {}, but no SNAT detected in trace",
                    expected_src_nat
                )
            })?;

            let matches = actual_nat == expected_src_nat;

            if verbose {
                if matches {
                    println!("    ✓ SNAT: {}", expected_src_nat);
                } else {
                    println!(
                        "    ✗ SNAT: expected {}, got {}",
                        expected_src_nat, actual_nat
                    );
                }
            }

            if !matches {
                return Ok(false);
            }
        }

        // Check DNAT
        if let Some(ref expected_dst_nat) = expectation.dst_nat {
            let actual_nat = trace_info.dst_nat.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "Expected DNAT to {}, but no DNAT detected in trace",
                    expected_dst_nat
                )
            })?;

            let matches = actual_nat == expected_dst_nat;

            if verbose {
                if matches {
                    println!("    ✓ DNAT: {}", expected_dst_nat);
                } else {
                    println!(
                        "    ✗ DNAT: expected {}, got {}",
                        expected_dst_nat, actual_nat
                    );
                }
            }

            if !matches {
                return Ok(false);
            }
        }
    }

    Ok(true)
}
