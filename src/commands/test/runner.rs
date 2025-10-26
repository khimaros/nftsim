// src/commands/test/runner.rs

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

// Use extracted modules
use super::guest::{
    GUEST_INJECTION_TIMEOUT_SECS, build_guest_injection_command, should_inject_from_guest,
};
use super::packet::build_test_frame;
use super::setup::{create_interface_socketpairs, generate_entrypoint_script};
use super::trace::parse_trace_for_packet;
use super::validation::validate_expectations_from_trace;

// Timing constants for test execution
const UML_BOOT_WAIT_SECS: u64 = 5; // Time to wait for UML to boot
const SOCKET_READ_TIMEOUT_MS: u64 = 10; // Socket read timeout for packet capture
const SOCKET_DRAIN_POLL_INTERVAL_MS: u64 = 50; // Polling interval for draining socket buffers
const TRACE_COLLECTION_WAIT_SECS: u64 = 1; // Wait for trace data to be written

/// Run a single simulation for a given config file.
async fn run_simulation(ruleset_file: &Path, config_path: &Path, args: &TestArgs) -> Result<()> {
    if !args.verbose {
        println!("\n=== Running tests from: {} ===", config_path.display());
    } else {
        println!(
            "\n--- Running simulation for: {} ---",
            config_path.display()
        );
    }

    let config: SimConfig = toml::from_str(&fs::read_to_string(config_path)?)?;
    let temp_dir = TempDir::new()?;

    // Always print temp directory early for debugging
    println!("Temporary directory: {}", temp_dir.path().display());

    // Get absolute path to temp directory for hostfs mount
    let hostfs_abs = temp_dir.path().canonicalize()?;

    // Generate main startup script (interface setup only)
    let entrypoint_script = generate_entrypoint_script(&config);
    let script_path = temp_dir.path().join("entrypoint.sh");
    fs::write(&script_path, entrypoint_script)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;

    // Write bundled harness.sh to temp dir
    let guest_setup_dst = temp_dir.path().join("harness.sh");
    fs::write(&guest_setup_dst, resources::HARNESS_SCRIPT)?;
    fs::set_permissions(&guest_setup_dst, fs::Permissions::from_mode(0o755))?;

    // Generate pre-nft commands script if needed
    if !config.guest_setup.pre_nft_commands.is_empty() {
        let pre_nft_script = format!(
            "#!/bin/sh\nset -eux\n{}",
            config.guest_setup.pre_nft_commands.join("\n")
        );
        let pre_nft_path = temp_dir.path().join("pre-nft-commands.sh");
        fs::write(&pre_nft_path, pre_nft_script)?;
        fs::set_permissions(&pre_nft_path, fs::Permissions::from_mode(0o755))?;
    }

    // Generate post-nft commands script if needed
    if !config.guest_setup.post_nft_commands.is_empty() {
        let post_nft_script = format!(
            "#!/bin/sh\nset -eux\n{}",
            config.guest_setup.post_nft_commands.join("\n")
        );
        let post_nft_path = temp_dir.path().join("post-nft-commands.sh");
        fs::write(&post_nft_path, post_nft_script)?;
        fs::set_permissions(&post_nft_path, fs::Permissions::from_mode(0o755))?;
    }

    // Copy ruleset to temp dir
    let staged_ruleset_path = temp_dir.path().join("rules.nft");
    fs::copy(ruleset_file, &staged_ruleset_path)?;
    if args.verbose {
        println!("Copied ruleset to {}", staged_ruleset_path.display());
    }

    let (orchestrator_sockets, uml_sockets) = create_interface_socketpairs(&config)?;

    // Message log files for bidirectional communication
    let host_to_guest_path = temp_dir.path().join("host_to_guest.txt");
    let guest_to_host_path = temp_dir.path().join("guest_to_host.txt");

    // Create empty message files
    std::fs::write(&host_to_guest_path, "")?;
    std::fs::write(&guest_to_host_path, "")?;

    if args.verbose {
        for iface in &config.network.interfaces {
            println!("Created socketpair for interface {}", iface.name);
        }
    }

    // Create a map of interface names to their socket indices
    let mut iface_to_socket: HashMap<String, usize> = HashMap::new();
    for (idx, iface) in config.network.interfaces.iter().enumerate() {
        iface_to_socket.insert(iface.name.clone(), idx);
    }

    let verbose = args.verbose;
    let trace_enabled = args.trace;
    let keep_temp = args.keep_temp;
    let timeout_secs = args.timeout;

    if !verbose {
        println!("Running {} test(s)...", config.test_cases.len());
    }

    // --- Launch UML Process ---
    let rootfs_img_abs = resources::get_rootfs_path()?;

    let mut uml_args = vec![
        "mem=256M".to_string(),
        format!("ubd0={}", rootfs_img_abs.display()),
        "rw".to_string(),
        format!("nftsim_tmpdir={}", hostfs_abs.display()),
        "init=/sbin/init.sh".to_string(),
    ];

    // Add kernel modules path as command line parameter if specified
    if !args.kernel_modules_path.is_empty() {
        uml_args.push(format!("nftsim_modules={}", args.kernel_modules_path));
    }

    // Configure vector network interfaces with fd transport
    // The FDs start at 3 because 0=stdin, 1=stdout, 2=stderr
    let mut next_fd = 3;
    for (idx, _iface) in config.network.interfaces.iter().enumerate() {
        // Set fixed MAC addresses for consistent packet addressing
        let mac = format!("00:00:00:00:00:{:02x}", idx + 1);
        uml_args.push(format!(
            "vec{}:transport=fd,fd={},mac={}",
            idx, next_fd, mac
        ));
        next_fd += 1;
    }

    if verbose {
        println!("Starting UML process...");
    }
    let mut cmd = Command::new(&args.kernel_binary_path);
    cmd.args(&uml_args);

    // Always redirect UML stdout/stderr to log files for analysis
    let uml_stdout_path = temp_dir.path().join("uml_stdout.log");
    let uml_stderr_path = temp_dir.path().join("uml_stderr.log");
    let uml_stdout =
        std::fs::File::create(&uml_stdout_path).context("Failed to create UML stdout log")?;
    let uml_stderr =
        std::fs::File::create(&uml_stderr_path).context("Failed to create UML stderr log")?;

    // Redirect stdin to /dev/null to prevent UML from accessing the terminal
    cmd.stdin(std::process::Stdio::null());

    // Always write UML output to files (can be inspected after with --keep-temp)
    cmd.stdout(std::process::Stdio::from(uml_stdout));
    cmd.stderr(std::process::Stdio::from(uml_stderr));

    // Pass the UML-side sockets as inherited file descriptors
    // We need to dup2 them to the correct FD numbers before exec
    unsafe {
        let socket_fds: Vec<i32> = uml_sockets.iter().map(|s| s.as_raw_fd()).collect();

        cmd.pre_exec(move || {
            // Dup interface sockets to FDs 3, 4, 5, ...
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

    let mut child = cmd.spawn().context("Failed to spawn UML process")?;

    // Spawn a task to inject test packets
    let test_config = config.clone();
    let mut sockets = orchestrator_sockets;
    let temp_dir_path = temp_dir.path().to_path_buf();
    let host_to_guest_path_clone = host_to_guest_path.clone();
    let guest_to_host_path_clone = guest_to_host_path.clone();
    tokio::spawn(async move {
        // Create log file for detailed output (always written, regardless of --verbose)
        let log_path = temp_dir_path.join("test.log");
        let mut log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .ok();

        // Helper macro to log and optionally print
        macro_rules! log {
            ($($arg:tt)*) => {
                if let Some(ref mut f) = log_file {
                    use std::io::Write;
                    let _ = writeln!(f, $($arg)*);
                }
                if verbose {
                    println!($($arg)*);
                }
            };
        }

        // Wait for UML guest to send READY message
        log!("\n=== Waiting for UML READY signal ===");

        // Poll for READY message in guest_to_host.txt
        let ready_timeout = Duration::from_secs(UML_BOOT_WAIT_SECS + 5);
        let poll_interval = Duration::from_millis(50);
        let start_time = std::time::Instant::now();
        let mut guest_ready = false;

        while start_time.elapsed() < ready_timeout {
            if let Ok(content) = std::fs::read_to_string(&guest_to_host_path_clone) {
                if content.lines().any(|line| line.trim() == "READY") {
                    log!("Received READY signal from guest");
                    guest_ready = true;
                    break;
                }
            }
            tokio::time::sleep(poll_interval).await;
        }

        if !guest_ready {
            log!("Warning: Timeout waiting for READY signal");
            log!("Proceeding anyway (guest may still be booting)");
        } else {
            log!("Guest boot complete and ready");
        }

        // Open trace.log for streaming (tail -f style)
        let trace_path = temp_dir_path.join("trace.log");
        log!("Opening trace.log for streaming...");

        // Wait a moment for trace file to be created
        let mut trace_file_ready = false;
        for _ in 0..20 {
            if trace_path.exists() {
                trace_file_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if !trace_file_ready {
            log!("Warning: trace.log not found, trace validation may fail");
        }

        // Open trace file for streaming - reads will block at EOF until new data arrives
        let mut trace_reader: Option<std::io::BufReader<std::fs::File>> =
            match std::fs::File::open(&trace_path) {
                Ok(f) => {
                    log!("Trace log opened for streaming");
                    if trace_enabled {
                        println!("\n=== nftables trace output (streaming) ===");
                    }
                    Some(std::io::BufReader::new(f))
                }
                Err(e) => {
                    log!("Warning: Failed to open trace.log: {}", e);
                    None
                }
            };

        // Keep accumulated trace content for parsing
        let mut accumulated_trace = String::new();

        // Drain any buffered data from sockets (boot messages, etc.)
        log!("Draining socket buffers...");
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
                log!("  Drained {} bytes from socket {}", total_drained, idx);
            }
        }

        if !verbose {
            println!();
        }

        let mut total_tests = 0;
        let mut passed_tests = 0;
        let mut failed_tests = 0;

        for test in &test_config.test_cases {
            total_tests += 1;
            let mut test_passed = true;

            log!("\nTest: {}", test.name);
            if !verbose {
                print!("  {} ... ", test.name);
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }

            for (step_num, step) in test.packets.iter().enumerate() {
                // Check if packet should be injected from guest
                let inject_from_guest = should_inject_from_guest(&step.packet, &test_config);

                if inject_from_guest {
                    log!(
                        "  Step {}: Injecting packet FROM GUEST on interface '{}'",
                        step_num + 1,
                        step.packet.on_interface
                    );

                    // Build and send guest injection command
                    match build_guest_injection_command(&step.packet) {
                        Ok(cmd) => {
                            // Append EXEC message to host_to_guest.txt
                            let message = format!("EXEC {}\n", cmd);
                            match std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&host_to_guest_path_clone)
                                .and_then(|mut f| {
                                    std::io::Write::write_all(&mut f, message.as_bytes())
                                }) {
                                Ok(_) => {
                                    log!("    ✓ Sent EXEC message to guest");
                                }
                                Err(e) => {
                                    log!("    ✗ Failed to write message: {}", e);
                                    test_passed = false;
                                    continue;
                                }
                            }

                            // Wait for ACK message in guest_to_host.txt
                            let max_wait = Duration::from_secs(GUEST_INJECTION_TIMEOUT_SECS + 1);
                            let poll_interval = Duration::from_millis(10);
                            let start = std::time::Instant::now();
                            let mut ack_received = false;
                            let mut last_ack_count = 0;

                            while start.elapsed() < max_wait {
                                if let Ok(content) =
                                    std::fs::read_to_string(&guest_to_host_path_clone)
                                {
                                    // Count ACK messages (each EXEC gets one ACK)
                                    let ack_count = content
                                        .lines()
                                        .filter(|line| line.starts_with("ACK "))
                                        .count();
                                    if ack_count > last_ack_count {
                                        // Found new ACK
                                        if let Some(ack_line) = content
                                            .lines()
                                            .filter(|line| line.starts_with("ACK "))
                                            .nth(ack_count - 1)
                                        {
                                            let exit_code = ack_line
                                                .strip_prefix("ACK ")
                                                .unwrap_or("0")
                                                .trim()
                                                .parse::<i32>()
                                                .unwrap_or(-1);
                                            if exit_code == 0 {
                                                log!("    ✓ Guest command completed successfully");
                                            } else {
                                                log!(
                                                    "    ! Guest command exited with code {}",
                                                    exit_code
                                                );
                                            }
                                            ack_received = true;
                                            break;
                                        }
                                    }
                                    last_ack_count = ack_count;
                                }
                                tokio::time::sleep(poll_interval).await;
                            }

                            if !ack_received {
                                log!("    ✗ Guest command timeout - no acknowledgment received");
                                test_passed = false;
                                continue;
                            }
                        }
                        Err(e) => {
                            log!("    ✗ Failed to build command: {}", e);
                            test_passed = false;
                            continue;
                        }
                    }

                    // For guest injection, keep reading trace until we find the packet or timeout
                    // Each packet generates multiple trace lines (packet + rules + verdict)
                    // so we need to keep reading for a bit after finding the packet
                    let search_timeout = Duration::from_secs(2);
                    let search_start = std::time::Instant::now();
                    let mut packet_found = false;
                    let mut packet_found_at: Option<std::time::Instant> = None;

                    while search_start.elapsed() < search_timeout {
                        // Read new lines from trace file
                        if let Some(mut reader) = trace_reader.take() {
                            match tokio::task::spawn_blocking(move || {
                                use std::io::BufRead;
                                let mut new_lines = String::new();
                                // Read up to 100 lines
                                for _ in 0..100 {
                                    let mut line = String::new();
                                    match reader.read_line(&mut line) {
                                        Ok(0) => break, // EOF
                                        Ok(_) => new_lines.push_str(&line),
                                        Err(_) => break,
                                    }
                                }
                                (reader, new_lines)
                            })
                            .await
                            {
                                Ok((reader_back, new_lines)) => {
                                    trace_reader = Some(reader_back);
                                    if !new_lines.is_empty() {
                                        accumulated_trace.push_str(&new_lines);

                                        // Print trace lines in real-time if --trace is enabled
                                        if trace_enabled {
                                            print!("{}", new_lines);
                                            std::io::Write::flush(&mut std::io::stdout()).ok();
                                        }

                                        // Quick check if packet might be present now
                                        if !packet_found
                                            && new_lines.contains(&step.packet.source_ip)
                                            && new_lines.contains(&step.packet.dest_ip)
                                        {
                                            packet_found = true;
                                            packet_found_at = Some(std::time::Instant::now());
                                        }
                                    }
                                }
                                Err(e) => {
                                    log!("    ✗ Failed to read trace: {}", e);
                                    break;
                                }
                            }
                        }

                        // After finding packet, read for another 100ms to get all associated trace lines
                        if let Some(found_at) = packet_found_at {
                            if found_at.elapsed() > Duration::from_millis(100) {
                                break;
                            }
                        }

                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                } else {
                    log!(
                        "  Step {}: Injecting packet from host on interface '{}'",
                        step_num + 1,
                        step.packet.on_interface
                    );

                    // Find the socket for this interface
                    if let Some(&socket_idx) = iface_to_socket.get(&step.packet.on_interface) {
                        // Build frame with correct destination MAC for this interface
                        let frame = build_test_frame(&step.packet, socket_idx);

                        if let Some(socket) = sockets.get_mut(socket_idx) {
                            // Inject the packet
                            match socket.write_all(&frame) {
                                Ok(_) => {
                                    log!("    ✓ Injected {} bytes", frame.len());
                                }
                                Err(e) => {
                                    log!("    ✗ Failed to inject: {}", e);
                                    test_passed = false;
                                    continue;
                                }
                            }
                        } else {
                            log!(
                                "    ✗ Socket not found for interface {}",
                                step.packet.on_interface
                            );
                            test_passed = false;
                            continue;
                        }
                    } else {
                        log!("    ✗ Unknown interface: {}", step.packet.on_interface);
                        test_passed = false;
                        continue;
                    }

                    // Host injection - read with small delay to get all trace lines
                    let packet_found_at = std::time::Instant::now();
                    while packet_found_at.elapsed() < Duration::from_millis(150) {
                        if let Some(mut reader) = trace_reader.take() {
                            match tokio::task::spawn_blocking(move || {
                                use std::io::BufRead;
                                let mut new_lines = String::new();
                                // Read up to 100 lines
                                for _ in 0..100 {
                                    let mut line = String::new();
                                    match reader.read_line(&mut line) {
                                        Ok(0) => break, // EOF
                                        Ok(_) => new_lines.push_str(&line),
                                        Err(_) => break,
                                    }
                                }
                                (reader, new_lines)
                            })
                            .await
                            {
                                Ok((reader_back, new_lines)) => {
                                    trace_reader = Some(reader_back);
                                    if !new_lines.is_empty() {
                                        accumulated_trace.push_str(&new_lines);

                                        // Print trace lines in real-time if --trace is enabled
                                        if trace_enabled {
                                            print!("{}", new_lines);
                                            std::io::Write::flush(&mut std::io::stdout()).ok();
                                        }
                                    }
                                }
                                Err(e) => {
                                    log!("    ✗ Failed to read trace: {}", e);
                                    break;
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }

                // Parse accumulated trace for our packet
                let trace_info = if !accumulated_trace.is_empty() {
                    // Extract ports based on transport protocol
                    let (src_port, dst_port) = match &step.packet.transport {
                        crate::config::Transport::Tcp(tcp) => {
                            (Some(tcp.source_port), Some(tcp.dest_port))
                        }
                        crate::config::Transport::Udp(udp) => {
                            (Some(udp.source_port), Some(udp.dest_port))
                        }
                        crate::config::Transport::Icmp(_) => (None, None),
                    };

                    // Build interface IP mapping for NAT resolution
                    let iface_ips: std::collections::HashMap<String, String> = test_config
                        .network
                        .interfaces
                        .iter()
                        .map(|iface| (iface.name.clone(), iface.ip.clone()))
                        .collect();

                    parse_trace_for_packet(
                        &accumulated_trace,
                        &step.packet.on_interface,
                        &step.packet.source_ip,
                        &step.packet.dest_ip,
                        src_port,
                        dst_port,
                        &iface_ips,
                    )
                } else {
                    None
                };

                // Validate expectations using trace only
                match validate_expectations_from_trace(step, trace_info.as_ref(), verbose) {
                    Ok(true) => {
                        // Test passed
                    }
                    Ok(false) => {
                        test_passed = false;
                    }
                    Err(e) => {
                        if verbose {
                            println!("    ✗ Validation error: {}", e);
                        }
                        test_passed = false;
                    }
                }

                tokio::time::sleep(Duration::from_millis(SOCKET_DRAIN_POLL_INTERVAL_MS)).await;
            }

            // Minimal delay between tests for trace to be written
            tokio::time::sleep(Duration::from_millis(SOCKET_DRAIN_POLL_INTERVAL_MS)).await;

            if test_passed {
                if !verbose {
                    println!("✓ PASS");
                }
                passed_tests += 1;
            } else {
                if !verbose {
                    println!("✗ FAIL");
                }
                failed_tests += 1;
            }
        }

        log!("");
        log!("=== Test Summary ===");
        log!(
            "Total: {}  Passed: {}  Failed: {}",
            total_tests,
            passed_tests,
            failed_tests
        );
        log!("\n=== Packet injection complete ===");

        // Also print summary to stdout always
        println!();
        println!("=== Test Summary ===");
        println!(
            "Total: {}  Passed: {}  Failed: {}",
            total_tests, passed_tests, failed_tests
        );

        // Trace output is now streamed in real-time during test execution

        // Signal UML to shutdown
        if verbose {
            println!("\n=== Signaling UML to shutdown ===");
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&host_to_guest_path_clone)
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"SHUTDOWN\n"))
        {
            Ok(_) => {
                if verbose {
                    println!("Sent SHUTDOWN message to guest");
                }
            }
            Err(e) => {
                if verbose {
                    println!("Warning: Could not write shutdown signal: {}", e);
                }
            }
        }

        // Give UML time to process shutdown
        tokio::time::sleep(Duration::from_secs(TRACE_COLLECTION_WAIT_SECS)).await;
        if verbose {
            println!();
        }
    });

    let timeout = Duration::from_secs(timeout_secs);
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            if verbose {
                println!("UML process finished with status: {}", status);
            }
            if !status.success() {
                eprintln!("Check logs in: {}", temp_dir.path().display());
                eprintln!("  - {}/test.log for verbose test output", temp_dir.path().display());
                eprintln!("  - {}/harness.log for guest boot log", temp_dir.path().display());
                eprintln!("  - {}/uml_stdout.log for UML kernel output", temp_dir.path().display());

                // Always preserve temp directory on error for debugging
                let path = temp_dir.path().to_path_buf();
                let _ = temp_dir.keep();
                eprintln!("Temporary directory preserved at: {}", path.display());

                bail!("UML process exited with an error code.");
            }
        }
        Ok(Err(e)) => return Err(e).context("Failed to wait for UML child process"),
        Err(_) => {
            child
                .kill()
                .await
                .context("Failed to kill UML process after timeout")?;

            // Always preserve temp directory on timeout for debugging
            let path = temp_dir.path().to_path_buf();
            let _ = temp_dir.keep();
            eprintln!("Temporary directory preserved at: {}", path.display());

            bail!("Simulation timed out after {} seconds.", timeout.as_secs());
        }
    }

    if verbose {
        println!(
            "Simulation finished. Results are in {}",
            temp_dir.path().display()
        );
    }

    // Keep temp directory if requested for debugging
    if keep_temp {
        let path = temp_dir.path().to_path_buf();
        let _ = temp_dir.keep();
        println!("Temporary directory preserved at: {}", path.display());
    }

    Ok(())
}

/// Perform pre-flight checks to ensure the environment is ready.
fn preflight_checks(args: &TestArgs) -> Result<()> {
    let rootfs_path = resources::get_rootfs_path()?;
    if !rootfs_path.exists() {
        bail!(
            "Root filesystem image '{}' not found. Please run the 'bootstrap' command first.",
            rootfs_path.display()
        );
    }
    if !args.kernel_binary_path.exists() {
        bail!(
            "User-Mode Linux kernel not found at '{}'. Please check --kernel-binary-path or install the 'user-mode-linux' package.",
            args.kernel_binary_path.display()
        );
    }
    // Check kernel modules path if specified
    if !args.kernel_modules_path.is_empty() {
        let modules_path = Path::new(&args.kernel_modules_path);
        if !modules_path.exists() {
            bail!(
                "Kernel modules path '{}' not found. Please check --kernel-modules-path or set to empty string to skip.",
                args.kernel_modules_path
            );
        }
    }
    if !args.ruleset_file.exists() {
        bail!("Ruleset file not found: {}", args.ruleset_file.display());
    }
    for config in &args.config_files {
        if !config.exists() {
            bail!("Config file not found: {}", config.display());
        }
    }
    Ok(())
}

/// Handle the `test` command.
pub async fn handle_test(mut args: TestArgs) -> Result<()> {
    if args.verbose {
        println!("--- Starting Test Command ---");
    }

    // Apply custom kernel paths if --kernel-custom flag is set
    if args.kernel_custom {
        let build_dir = resources::get_build_dir()?.join("linux");
        args.kernel_binary_path = build_dir.join("linux");

        // Find the kernel version directory in prefix/lib/modules/
        let modules_base = build_dir.join("prefix/lib/modules");

        args.kernel_modules_path = modules_base.as_path().to_string_lossy().to_string();
        if args.verbose {
            println!("Using custom kernel: {}", args.kernel_binary_path.display());
            println!("Using custom modules: {}", args.kernel_modules_path);
        }
    }

    preflight_checks(&args)?;
    if args.verbose {
        println!("Pre-flight checks passed.");
    }

    for config_path in &args.config_files {
        run_simulation(&args.ruleset_file, config_path, &args).await?;
    }

    Ok(())
}
