use crate::cli::TestArgs;
use crate::config::SimConfig;
use crate::resources;
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;

use super::guest::{
    GUEST_INJECTION_TIMEOUT_SECS, build_guest_injection_command, should_inject_from_guest,
};
use super::packet::build_test_frame;
use super::report::{CaseResult, Report, SuiteReport};
use super::setup::{create_interface_socketpairs, generate_entrypoint_script};
use super::trace::{
    find_unrecognized_trace_lines, parse_chain_hooks, parse_conntrack_snat, parse_trace_for_packet,
};
use super::validation::validate_expectations_from_trace;

const READY_TIMEOUT_SECS: u64 = 45;
const SOCKET_READ_TIMEOUT_MS: u64 = 10;
const SOCKET_DRAIN_POLL_INTERVAL_MS: u64 = 50;
// grace window for the injector task to finish reading SHUTDOWN's ACK if UML halts first
const INJECTOR_FINISH_GRACE_SECS: u64 = 2;
// a loaded host can delay trace lines well past any fixed window, so read until
// the packet shows up and the monitor goes quiet, giving up after the timeout
const TRACE_SEARCH_TIMEOUT_MS: u64 = 3000;
const TRACE_QUIET_MS: u64 = 150;
const TRACE_POLL_INTERVAL_MS: u64 = 10;

// the guest dumps its conntrack table here so masquerade can be read, not guessed
const CONNTRACK_DUMP_FILE: &str = "conntrack.txt";
const TRACE_MONITOR_ERR_FILE: &str = "trace_monitor.err";

/// send one control message (EXEC or SHUTDOWN) over the file-based channel and
/// return its ACK code. each message gets one ACK, so the first ACK beyond
/// those already present answers this message
async fn send_guest_message(
    host_to_guest: &Path,
    guest_to_host: &Path,
    message: &str,
) -> Result<i32> {
    let acks = || -> Vec<String> {
        fs::read_to_string(guest_to_host)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("ACK ").map(str::to_string))
            .collect()
    };
    let acks_before = acks().len();
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(host_to_guest)
        .and_then(|mut f| f.write_all(format!("{}\n", message).as_bytes()))
        .context("failed to write message")?;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(GUEST_INJECTION_TIMEOUT_SECS + 1) {
        if let Some(code) = acks().get(acks_before) {
            return Ok(code.trim().parse().unwrap_or(-1));
        }
        tokio::time::sleep(Duration::from_millis(TRACE_POLL_INTERVAL_MS)).await;
    }
    bail!("guest command timeout - no acknowledgment received")
}

/// run a shell command in the guest and return its exit code
async fn run_in_guest(host_to_guest: &Path, guest_to_host: &Path, cmd: &str) -> Result<i32> {
    send_guest_message(host_to_guest, guest_to_host, &format!("EXEC {}", cmd)).await
}

/// read whatever the trace monitor has appended since the last call
fn read_new_trace(reader: &mut std::io::BufReader<std::fs::File>) -> String {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// append any newly written trace bytes to `trace`, echoing when `--trace` is on
fn drain_trace_to(
    reader: &mut std::io::BufReader<std::fs::File>,
    trace: &mut String,
    echo: bool,
) -> bool {
    let new_lines = read_new_trace(reader);
    if new_lines.is_empty() {
        return false;
    }
    if echo {
        print!("{}", new_lines);
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }
    trace.push_str(&new_lines);
    true
}

/// keep the temporary directory on failure and tell the user where its logs are
fn preserve_temp_dir(temp_dir: TempDir) {
    let path = temp_dir.path().to_path_buf();
    eprintln!("check logs in: {}", path.display());
    eprintln!("  - {}/test.log for verbose test output", path.display());
    eprintln!("  - {}/harness.log for guest boot log", path.display());
    eprintln!("  - {}/uml_stdout.log for UML kernel output", path.display());
    let _ = temp_dir.keep();
    eprintln!("temporary directory preserved at: {}", path.display());
}

/// append trace output to `trace` until `is_found` matches the part read by
/// this call and no new lines have arrived for TRACE_QUIET_MS, so every hook
/// the packet traverses makes it in even when the guest is slow.
async fn collect_packet_trace(
    reader: &mut std::io::BufReader<std::fs::File>,
    trace: &mut String,
    echo: bool,
    is_found: impl Fn(&str) -> bool,
) {
    let start_len = trace.len();
    let start = std::time::Instant::now();
    let mut last_growth = start;
    let mut found = false;
    while start.elapsed() < Duration::from_millis(TRACE_SEARCH_TIMEOUT_MS) {
        if drain_trace_to(reader, trace, echo) {
            last_growth = std::time::Instant::now();
            found = found || is_found(&trace[start_len..]);
        }
        if found && last_growth.elapsed() >= Duration::from_millis(TRACE_QUIET_MS) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(TRACE_POLL_INTERVAL_MS)).await;
    }
}

/// boot a UML guest with the ruleset loaded, run every test case in the
/// config against it, and return the test log and the result of each case
pub async fn run_simulation(
    ruleset_file: &Path,
    config: SimConfig,
    config_name: &str,
    args: &TestArgs,
) -> Result<(String, Vec<CaseResult>)> {
    if !args.verbose {
        println!("\n=== running tests from: {} ===", config_name);
    } else {
        println!(
            "\n--- running simulation for: {} ---",
            config_name
        );
    }

    let temp_dir = TempDir::new()?;

    // printed up front so a hung run can still be inspected
    println!("temporary directory: {}", temp_dir.path().display());

    // the guest mounts this directory through hostfs, which needs an absolute path
    let hostfs_abs = temp_dir.path().canonicalize()?;

    let entrypoint_script = generate_entrypoint_script(&config);
    let script_path = temp_dir.path().join("entrypoint.sh");
    fs::write(&script_path, entrypoint_script)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;

    let guest_setup_dst = temp_dir.path().join("harness.sh");
    fs::write(&guest_setup_dst, resources::HARNESS_SCRIPT)?;
    fs::set_permissions(&guest_setup_dst, fs::Permissions::from_mode(0o755))?;

    // harness.sh runs these scripts around the ruleset load when they exist
    if !config.guest_setup.pre_nft_commands.is_empty() {
        let pre_nft_script = format!(
            "#!/bin/sh\nset -eux\n{}",
            config.guest_setup.pre_nft_commands.join("\n")
        );
        let pre_nft_path = temp_dir.path().join("pre-nft-commands.sh");
        fs::write(&pre_nft_path, pre_nft_script)?;
        fs::set_permissions(&pre_nft_path, fs::Permissions::from_mode(0o755))?;
    }

    if !config.guest_setup.post_nft_commands.is_empty() {
        let post_nft_script = format!(
            "#!/bin/sh\nset -eux\n{}",
            config.guest_setup.post_nft_commands.join("\n")
        );
        let post_nft_path = temp_dir.path().join("post-nft-commands.sh");
        fs::write(&post_nft_path, post_nft_script)?;
        fs::set_permissions(&post_nft_path, fs::Permissions::from_mode(0o755))?;
    }

    let staged_ruleset_path = temp_dir.path().join("rules.nft");
    fs::copy(ruleset_file, &staged_ruleset_path)?;
    if args.verbose {
        println!("copied ruleset to {}", staged_ruleset_path.display());
    }

    let (orchestrator_sockets, uml_sockets) = create_interface_socketpairs(&config)?;

    // host and guest exchange line-based messages (READY, EXEC, ACK, SHUTDOWN)
    // through append-only files on the shared hostfs mount
    let host_to_guest_path = temp_dir.path().join("host_to_guest.txt");
    let guest_to_host_path = temp_dir.path().join("guest_to_host.txt");

    std::fs::write(&host_to_guest_path, "")?;
    std::fs::write(&guest_to_host_path, "")?;

    if args.verbose {
        for iface in &config.network.interfaces {
            println!("created socketpair for interface {}", iface.name);
        }
    }

    let mut iface_to_socket: HashMap<String, usize> = HashMap::new();
    for (idx, iface) in config.network.interfaces.iter().enumerate() {
        iface_to_socket.insert(iface.name.clone(), idx);
    }

    let verbose = args.verbose;
    let trace_enabled = args.trace;
    let keep_temp = args.keep_temp;
    let timeout_secs = args.timeout;

    if !verbose {
        println!("running {} test(s)...", config.test_cases.len());
    }

    let rootfs_img_abs = resources::get_rootfs_path()?;
    // writes go to a per-run copy-on-write overlay: UML then opens the shared
    // image read-only with a shared lock, so concurrent runs can boot from it
    let rootfs_cow = hostfs_abs.join("rootfs.cow");

    let mut uml_args = vec![
        "mem=256M".to_string(),
        format!("ubd0={},{}", rootfs_cow.display(), rootfs_img_abs.display()),
        "rw".to_string(),
        format!("nftsim_tmpdir={}", hostfs_abs.display()),
        "init=/sbin/init.sh".to_string(),
    ];

    if !args.kernel_modules_path.is_empty() {
        uml_args.push(format!("nftsim_modules={}", args.kernel_modules_path));
    }

    // vector interfaces use the fd transport, starting after stdin/stdout/stderr,
    // with fixed MAC addresses so injected frames can be addressed to them
    let mut next_fd = 3;
    for (idx, _iface) in config.network.interfaces.iter().enumerate() {
        let mac = format!("00:00:00:00:00:{:02x}", idx + 1);
        uml_args.push(format!(
            "vec{}:transport=fd,fd={},mac={}",
            idx, next_fd, mac
        ));
        next_fd += 1;
    }

    if verbose {
        println!("starting UML process...");
    }
    let mut cmd = Command::new(&args.kernel_binary_path);
    cmd.args(&uml_args);

    // UML output goes to log files, which --keep-temp preserves for inspection
    let uml_stdout_path = temp_dir.path().join("uml_stdout.log");
    let uml_stderr_path = temp_dir.path().join("uml_stderr.log");
    let uml_stdout =
        std::fs::File::create(&uml_stdout_path).context("failed to create UML stdout log")?;
    let uml_stderr =
        std::fs::File::create(&uml_stderr_path).context("failed to create UML stderr log")?;

    // keep UML away from the terminal
    cmd.stdin(std::process::Stdio::null());

    cmd.stdout(std::process::Stdio::from(uml_stdout));
    cmd.stderr(std::process::Stdio::from(uml_stderr));

    // UML expects the interface sockets at FDs 3, 4, 5, ... (see the vec
    // arguments above), so dup2 them into place before exec
    unsafe {
        let socket_fds: Vec<i32> = uml_sockets.iter().map(|s| s.as_raw_fd()).collect();

        cmd.pre_exec(move || {
            for (idx, &fd) in socket_fds.iter().enumerate() {
                let target_fd = (3 + idx) as i32;
                if fd != target_fd {
                    let result = libc::dup2(fd, target_fd);
                    if result == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }

            Ok(())
        });
    }

    let mut child = cmd.spawn().context("failed to spawn UML process")?;

    // the injector drives the test cases while the main task waits on UML
    let test_config = config.clone();
    let mut sockets = orchestrator_sockets;
    let temp_dir_path = temp_dir.path().to_path_buf();
    let host_to_guest_path_clone = host_to_guest_path.clone();
    let guest_to_host_path_clone = guest_to_host_path.clone();
    // return sockets with the results so they stay open until UML halts;
    // closing them early spins UML's vector driver on POLLHUP
    let mut injector: tokio::task::JoinHandle<Result<(Vec<CaseResult>, Vec<std::os::unix::net::UnixStream>)>> =
        tokio::spawn(async move {
        // detailed output always goes to test.log, and to stdout with --verbose
        let log_path = temp_dir_path.join("test.log");
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        macro_rules! log {
            ($($arg:tt)*) => {{
                let msg = format!($($arg)*);
                if let Some(ref mut f) = log_file {
                    use std::io::Write;
                    let _ = writeln!(f, "{}", msg);
                }
                if verbose {
                    println!("{}", msg);
                }
            }};
        }

        log!("\n=== waiting for UML READY signal ===");

        let ready_timeout_secs = READY_TIMEOUT_SECS.min((timeout_secs / 2).max(1));
        let ready_timeout = Duration::from_secs(ready_timeout_secs);
        let poll_interval = Duration::from_millis(50);
        let start_time = std::time::Instant::now();
        let mut guest_ready = false;

        while start_time.elapsed() < ready_timeout {
            if let Ok(content) = std::fs::read_to_string(&guest_to_host_path_clone) {
                if content.lines().any(|line| line.trim() == "READY") {
                    log!("received READY signal from guest");
                    guest_ready = true;
                    break;
                }
            }
            tokio::time::sleep(poll_interval).await;
        }

        if !guest_ready {
            log!("error: timeout waiting for READY signal");
            bail!("timeout waiting for guest READY signal after {}s", ready_timeout_secs);
        }
        log!("guest boot complete and ready");

        // the harness records each base chain's hook after loading the ruleset,
        // so traces from chains not named after their hook resolve correctly
        let chains_json = fs::read_to_string(temp_dir_path.join("chains.json"))
            .context("failed to read chains.json after guest reported READY")?;
        let chain_hooks = parse_chain_hooks(&chains_json);

        let trace_path = temp_dir_path.join("trace.log");
        log!("opening trace.log for streaming...");

        let mut trace_file_ready = false;
        for _ in 0..20 {
            if trace_path.exists() {
                trace_file_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if !trace_file_ready {
            bail!("trace.log not found after guest reported READY");
        }

        // reads return what was appended since the last one, tail -f style
        let trace_file = std::fs::File::open(&trace_path).context("failed to open trace.log")?;
        log!("trace log opened for streaming");
        if trace_enabled {
            println!("\n=== nftables trace output (streaming) ===");
        }
        let mut trace_reader = std::io::BufReader::new(trace_file);

        let mut accumulated_trace = String::new();

        // discard frames the guest sent while booting
        log!("draining socket buffers...");
        for (idx, socket) in sockets.iter_mut().enumerate() {
            socket
                .set_read_timeout(Some(Duration::from_millis(SOCKET_READ_TIMEOUT_MS)))
                .ok();
            let mut buf = vec![0u8; 4096];
            let mut total_drained = 0;
            loop {
                match socket.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        total_drained += n;
                    }
                    _ => break,
                }
            }
            if total_drained > 0 {
                log!("  drained {} bytes from socket {}", total_drained, idx);
            }
        }

        if !verbose {
            println!();
        }

        let mut total_tests = 0;
        let mut passed_tests = 0;
        let mut failed_tests = 0;
        let mut results: Vec<CaseResult> = Vec::new();
        // interface addresses let trace parsing resolve masquerade
        let iface_ips: HashMap<String, Vec<String>> = test_config
            .network
            .interfaces
            .iter()
            .map(|iface| (iface.name.clone(), iface.addresses().map(str::to_string).collect()))
            .collect();

        for test in &test_config.test_cases {
            total_tests += 1;
            // the first thing that went wrong in this case, for the report
            let mut failure: Option<String> = None;

            log!("\ntest: {}", test.name);
            if !verbose {
                print!("  {} ... ", test.name);
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }

            for (step_num, step) in test.packets.iter().enumerate() {
                // drain idle guest traffic first so this step only searches trace
                // output produced after its own packet is injected
                drain_trace_to(&mut trace_reader, &mut accumulated_trace, trace_enabled);
                let step_trace_start = accumulated_trace.len();

                let inject_from_guest = should_inject_from_guest(&step.packet, &test_config);

                if inject_from_guest {
                    log!(
                        "  step {}: injecting packet FROM GUEST on interface '{}'",
                        step_num + 1,
                        step.packet.on_interface
                    );

                    let sent = match build_guest_injection_command(&step.packet) {
                        Ok(cmd) => run_in_guest(&host_to_guest_path_clone, &guest_to_host_path_clone, &cmd).await,
                        Err(e) => Err(e.context("failed to build command")),
                    };
                    match sent {
                        Ok(0) => log!("    ok guest command completed successfully"),
                        Ok(code) => log!("    ! guest command exited with code {}", code),
                        Err(e) => {
                            log!("    x {:#}", e);
                            failure.get_or_insert(format!("{:#}", e));
                            continue;
                        }
                    }
                } else {
                    log!(
                        "  step {}: injecting packet from host on interface '{}'",
                        step_num + 1,
                        step.packet.on_interface
                    );

                    if let Some(&socket_idx) = iface_to_socket.get(&step.packet.on_interface) {
                        let frame = build_test_frame(&step.packet, socket_idx);

                        if let Some(socket) = sockets.get_mut(socket_idx) {
                            match socket.write_all(&frame) {
                                Ok(_) => {
                                    log!("    ok injected {} bytes", frame.len());
                                }
                                Err(e) => {
                                    log!("    x failed to inject: {}", e);
                                    failure.get_or_insert(format!("failed to inject: {}", e));
                                    continue;
                                }
                            }
                        } else {
                            log!(
                                "    x socket not found for interface {}",
                                step.packet.on_interface
                            );
                            failure.get_or_insert(format!("socket not found for interface {}", step.packet.on_interface));
                            continue;
                        }
                    } else {
                        log!("    x unknown interface: {}", step.packet.on_interface);
                        failure.get_or_insert(format!("unknown interface: {}", step.packet.on_interface));
                        continue;
                    }
                }

                let (src_port, dst_port) = match &step.packet.transport {
                    crate::config::Transport::Tcp(tcp) => {
                        (Some(tcp.source_port), Some(tcp.dest_port))
                    }
                    crate::config::Transport::Udp(udp) => {
                        (Some(udp.source_port), Some(udp.dest_port))
                    }
                    crate::config::Transport::Icmp(_) => (None, None),
                };
                let find_packet = |trace: &str| {
                    parse_trace_for_packet(
                        trace,
                        &step.packet.on_interface,
                        &step.packet.source_ip,
                        &step.packet.dest_ip,
                        src_port,
                        dst_port,
                        &iface_ips,
                        &chain_hooks,
                    )
                };
                collect_packet_trace(&mut trace_reader, &mut accumulated_trace, trace_enabled, |t| {
                    find_packet(t).is_some()
                })
                .await;
                let mut trace_info = find_packet(&accumulated_trace[step_trace_start..]);

                // masquerade picks its address at runtime (the one facing the
                // route's gateway), so ask the guest's conntrack table which
                // address it chose instead of trusting the config-based guess
                if let Some(info) = trace_info.as_mut().filter(|info| info.masquerade) {
                    let dump = format!("cat /proc/net/nf_conntrack > /mnt/host/{}", CONNTRACK_DUMP_FILE);
                    match run_in_guest(&host_to_guest_path_clone, &guest_to_host_path_clone, &dump).await {
                        Ok(_) => {
                            let table = fs::read_to_string(temp_dir_path.join(CONNTRACK_DUMP_FILE)).unwrap_or_default();
                            match parse_conntrack_snat(&table, &step.packet.source_ip, &step.packet.dest_ip, src_port, dst_port) {
                                Some(addr) => info.src_nat = Some(addr),
                                None => log!("    ! no conntrack entry, masquerade address is a guess"),
                            }
                        }
                        Err(e) => log!("    ! could not read conntrack: {:#}", e),
                    }
                }

                match validate_expectations_from_trace(step, trace_info.as_ref(), verbose) {
                    Ok(None) => {}
                    Ok(Some(reason)) => {
                        failure.get_or_insert(format!("step {}: {}", step_num + 1, reason));
                    }
                    Err(e) => {
                        if verbose {
                            println!("    x validation error: {}", e);
                        }
                        failure.get_or_insert(format!("step {}: {}", step_num + 1, e));
                    }
                }

                tokio::time::sleep(Duration::from_millis(SOCKET_DRAIN_POLL_INTERVAL_MS)).await;
            }

            // a short gap keeps trace lines from one test out of the next
            tokio::time::sleep(Duration::from_millis(SOCKET_DRAIN_POLL_INTERVAL_MS)).await;

            if failure.is_none() {
                log!("result: pass");
                if !verbose {
                    println!("pass");
                }
                passed_tests += 1;
            } else {
                log!("result: fail");
                if !verbose {
                    println!("fail");
                }
                failed_tests += 1;
            }
            results.push(CaseResult {
                name: test.name.clone(),
                passed: failure.is_none(),
                reason: failure,
            });
        }

        log!("");
        log!("=== test summary ===");
        log!(
            "total: {}  passed: {}  failed: {}",
            total_tests,
            passed_tests,
            failed_tests
        );
        log!("\n=== packet injection complete ===");

        // the summary goes to stdout even without --verbose
        println!();
        println!("=== test summary ===");
        println!(
            "total: {}  passed: {}  failed: {}",
            total_tests, passed_tests, failed_tests
        );

        if verbose {
            println!("\n=== signaling UML to shutdown ===");
        }
        let shutdown_ack = send_guest_message(
            &host_to_guest_path_clone,
            &guest_to_host_path_clone,
            "SHUTDOWN",
        )
        .await
        .context("guest did not acknowledge SHUTDOWN")?;
        if verbose {
            println!("sent SHUTDOWN message to guest (ack {})", shutdown_ack);
        }

        // capture any remaining trace lines flushed before the monitor is stopped
        drain_trace_to(&mut trace_reader, &mut accumulated_trace, trace_enabled);
        if verbose {
            println!();
        }

        if shutdown_ack != 0 {
            let monitor_err = fs::read_to_string(temp_dir_path.join(TRACE_MONITOR_ERR_FILE))
                .unwrap_or_default();
            let detail = monitor_err.trim();
            if detail.is_empty() {
                bail!("trace monitor died before simulation finished");
            }
            bail!("trace monitor died before simulation finished: {}", detail);
        }

        let unrecognized = find_unrecognized_trace_lines(&accumulated_trace);
        if !unrecognized.is_empty() {
            bail!(
                "found {} unrecognized line(s) in trace output (first: {:?})",
                unrecognized.len(),
                unrecognized[0]
            );
        }

        Ok((results, sockets))
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let results = tokio::select! {
        res = &mut injector => {
            match res.context("packet injection task failed")? {
                Ok((results, _sockets)) => {
                    match tokio::time::timeout_at(deadline, child.wait()).await {
                        Ok(Ok(status)) => {
                            if verbose {
                                println!("UML process finished with status: {}", status);
                            }
                            if !status.success() {
                                preserve_temp_dir(temp_dir);
                                bail!("UML process exited with an error code");
                            }
                            results
                        }
                        Ok(Err(e)) => return Err(e).context("failed to wait for UML child process"),
                        Err(_) => {
                            let _ = child.kill().await;
                            preserve_temp_dir(temp_dir);
                            bail!("simulation timed out after {} seconds", timeout_secs);
                        }
                    }
                }
                Err(e) => {
                    let _ = child.kill().await;
                    preserve_temp_dir(temp_dir);
                    return Err(e);
                }
            }
        }
        status = child.wait() => {
            let status = status.context("failed to wait for UML child process")?;
            if verbose {
                println!("UML process finished with status: {}", status);
            }
            if !status.success() {
                injector.abort();
                preserve_temp_dir(temp_dir);
                bail!("UML process exited with an error code");
            }
            // UML may halt cleanly right as the injector reads SHUTDOWN's ACK
            let grace = Duration::from_secs(INJECTOR_FINISH_GRACE_SECS);
            match tokio::time::timeout(grace, &mut injector).await {
                Ok(res) => match res.context("packet injection task failed")? {
                    Ok((results, _sockets)) => results,
                    Err(e) => {
                        preserve_temp_dir(temp_dir);
                        return Err(e);
                    }
                },
                Err(_) => {
                    injector.abort();
                    preserve_temp_dir(temp_dir);
                    bail!("UML process exited before simulation completed");
                }
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            injector.abort();
            let _ = child.kill().await;
            preserve_temp_dir(temp_dir);
            bail!("simulation timed out after {} seconds", timeout_secs);
        }
    };

    if verbose {
        println!(
            "simulation finished. results are in {}",
            temp_dir.path().display()
        );
    }

    // read the log before the temp dir is dropped
    let log_path = temp_dir.path().join("test.log");
    let log_content = fs::read_to_string(&log_path)
        .context("failed to read test log")
        .unwrap_or_else(|e| format!("error reading log: {}", e));

    if keep_temp {
        let path = temp_dir.path().to_path_buf();
        let _ = temp_dir.keep();
        println!("temporary directory preserved at: {}", path.display());
    }

    Ok((log_content, results))
}

/// fail early with an actionable message when a required file is missing
fn preflight_checks(args: &TestArgs) -> Result<()> {
    let rootfs_path = resources::get_rootfs_path()?;
    if !rootfs_path.exists() {
        bail!(
            "root filesystem image '{}' not found. please run the 'bootstrap' command first.",
            rootfs_path.display()
        );
    }
    if !args.kernel_binary_path.exists() {
        bail!(
            "User-Mode Linux kernel not found at '{}'. please check --kernel-binary-path or install the 'user-mode-linux' package.",
            args.kernel_binary_path.display()
        );
    }
    if !args.kernel_modules_path.is_empty() {
        let modules_path = Path::new(&args.kernel_modules_path);
        if !modules_path.exists() {
            bail!(
                "kernel modules path '{}' not found. please check --kernel-modules-path or set to empty string to skip.",
                args.kernel_modules_path
            );
        }
    }
    if !args.ruleset_file.exists() {
        bail!("file not found: {}", args.ruleset_file.display());
    }
    for config in &args.config_files {
        if !config.exists() {
            bail!("config file not found: {}", config.display());
        }
    }
    Ok(())
}

/// handle the `test` command: resolve kernel paths, run each suite (or the
/// ruleset's embedded tests), write the report, and fail if any case failed
pub async fn handle_test(mut args: TestArgs) -> Result<()> {
    if args.verbose {
        println!("--- starting test command ---");
    }

    if args.kernel_custom {
        args.kernel_binary_path = resources::get_kernel_binary_path()?;
        let build_dir = resources::get_build_dir()?.join("linux");

        let modules_base = build_dir.join("prefix/lib/modules");

        args.kernel_modules_path = modules_base.as_path().to_string_lossy().to_string();
        if args.verbose {
            println!("using custom kernel: {}", args.kernel_binary_path.display());
            println!("using custom modules: {}", args.kernel_modules_path);
        }
    }

    preflight_checks(&args)?;
    if args.verbose {
        println!("pre-flight checks passed.");
    }

    // `nftsim test suite.toml ...`: the first argument is itself a suite, and
    // each suite names its own ruleset
    let explicit_ruleset = if args.ruleset_file.extension().is_some_and(|ext| ext == "toml") {
        args.config_files.insert(0, args.ruleset_file.clone());
        None
    } else {
        Some(args.ruleset_file.clone())
    };

    let mut suites = Vec::new();
    if args.config_files.is_empty() {
        if args.verbose {
            println!("no config files provided, looking for embedded tests in ruleset...");
        }
        let rules_content = fs::read_to_string(&args.ruleset_file)
            .context("failed to read ruleset file for embedded tests")?;

        let config = super::embedded::parse_embedded_tests(&rules_content)
            .context("failed to parse embedded tests")?;

        if config.test_cases.is_empty() {
            bail!("no config files provided and no embedded tests found in ruleset");
        }

        let name = format!("{} (embedded)", args.ruleset_file.display());
        let (_, tests) = run_simulation(&args.ruleset_file, config, &name, &args).await?;
        suites.push(SuiteReport { config: name, ruleset: args.ruleset_file.display().to_string(), tests });

    } else {
        for config_path in &args.config_files {
            let config_content = fs::read_to_string(config_path)
                .with_context(|| format!("failed to read config file: {}", config_path.display()))?;
            let config: SimConfig = toml::from_str(&config_content)
                .with_context(|| format!("failed to parse config file: {}", config_path.display()))?;

            // a ruleset given on the command line wins over the suite's own
            let ruleset = explicit_ruleset
                .clone()
                .or_else(|| config.ruleset_path(config_path))
                .with_context(|| format!(
                    "{} names no ruleset: pass one before it or set `ruleset` in it",
                    config_path.display()
                ))?;
            if !ruleset.exists() {
                bail!("ruleset file not found: {}", ruleset.display());
            }

            let name = config_path.to_string_lossy().to_string();
            let (_, tests) = run_simulation(&ruleset, config, &name, &args).await?;
            suites.push(SuiteReport { config: name, ruleset: ruleset.display().to_string(), tests });
        }
    }

    let report = Report::new(suites);
    if let Some(ref path) = args.report {
        fs::write(path, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("failed to write report: {}", path.display()))?;
    }
    if report.failed > 0 {
        bail!("{} of {} test(s) failed", report.failed, report.total);
    }

    Ok(())
}
