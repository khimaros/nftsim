#!/bin/sh
# Guest setup script for nftsim
# This runs inside the UML guest and sets up the test environment
#
# Prerequisites:
# - /mnt/host/rules.nft - nftables ruleset to load
# - /mnt/host/post-nft-commands.sh (optional) - additional commands to run after nft load
# - /mnt/host/shutdown (created by orchestrator to signal shutdown)
#
# Outputs:
# - /mnt/host/trace.log - nftables trace output

set -e

echo "NFTsim guest setup starting" | tee -a /mnt/host/harness.log

# Network interfaces are already configured by orchestrator before this script runs

# Run any pre-nft commands from config
if [ -f /mnt/host/pre-nft-commands.sh ]; then
  echo "Running pre-nft commands..." | tee -a /mnt/host/harness.log
  sh /mnt/host/pre-nft-commands.sh
fi

# Load nftables ruleset
echo "Loading nftables ruleset..." | tee -a /mnt/host/harness.log
nft -f /mnt/host/rules.nft
echo "Ruleset loaded successfully" | tee -a /mnt/host/harness.log

# Dynamically discover all chains and enable tracing
echo "Enabling nftables trace for all chains..." | tee -a /mnt/host/harness.log
# Get list of all tables in format "family tablename"
nft list tables | while read family_table; do
  # Parse "inet filter" -> family="inet" table="filter"
  family=$(echo "$family_table" | awk '{print $2}')
  table=$(echo "$family_table" | awk '{print $3}')

  if [ -n "$family" ] && [ -n "$table" ]; then
    # Get all chains in this table
    nft list table "$family" "$table" 2>/dev/null | grep "^\s*chain " | awk '{print $2}' | while read chain; do
      if [ -n "$chain" ]; then
        echo "  Enabling trace for $family $table $chain"
        nft insert rule "$family" "$table" "$chain" meta nftrace set 1 2>/dev/null || echo "    Failed"
      fi
    done
  fi
done

# Start trace monitor
echo "Starting nft monitor trace..." | tee -a /mnt/host/harness.log
nft monitor trace > /mnt/host/trace.log &
TRACE_PID=$!
echo "Trace monitor PID: $TRACE_PID" | tee -a /mnt/host/harness.log

# Run any post-nft commands from config
if [ -f /mnt/host/post-nft-commands.sh ]; then
  echo "Running post-nft commands..." | tee -a /mnt/host/harness.log
  sh /mnt/host/post-nft-commands.sh
fi

# Start command listener - tail host_to_guest messages
echo "Starting command listener..." | tee -a /mnt/host/harness.log

(
  # Track last read line number
  last_line=0
  shutdown_received=0

  while [ "$shutdown_received" -eq 0 ]; do
    # Read new lines from host_to_guest.txt
    if [ -f /mnt/host/host_to_guest.txt ]; then
      current_lines=$(wc -l < /mnt/host/host_to_guest.txt 2>/dev/null || echo 0)

      if [ "$current_lines" -gt "$last_line" ]; then
        # Process each new line
        line_num=$((last_line + 1))
        while [ "$line_num" -le "$current_lines" ]; do
          # Read specific line
          line=$(sed -n "${line_num}p" /mnt/host/host_to_guest.txt 2>/dev/null)

          if [ -n "$line" ]; then
            # Split on first space
            msg_type="${line%% *}"
            msg_data="${line#* }"

            case "$msg_type" in
              EXEC)
                echo "[$(date +%H:%M:%S)] EXEC: $msg_data" >> /mnt/host/commands.log
                eval "$msg_data" >> /mnt/host/commands.log 2>&1
                exit_code=$?
                echo "[$(date +%H:%M:%S)] Exit: $exit_code" >> /mnt/host/commands.log

                # Send acknowledgment
                echo "ACK $exit_code" >> /mnt/host/guest_to_host.txt
                ;;
              SHUTDOWN)
                echo "[$(date +%H:%M:%S)] SHUTDOWN" >> /mnt/host/commands.log
                echo "ACK 0" >> /mnt/host/guest_to_host.txt
                shutdown_received=1
                ;;
            esac
          fi

          line_num=$((line_num + 1))
        done
        last_line=$current_lines
      fi
    fi

    sleep 0.01  # Fast polling - 10ms
  done
) &
CMD_LISTENER_PID=$!
echo "Command listener PID: $CMD_LISTENER_PID" | tee -a /mnt/host/harness.log

echo "Guest setup complete, waiting for shutdown signal..." | tee -a /mnt/host/harness.log

# Send READY signal to host
echo "READY" >> /mnt/host/guest_to_host.txt
echo "Sent READY signal to host" | tee -a /mnt/host/harness.log

# Wait for command listener to exit (on SHUTDOWN message)
wait $CMD_LISTENER_PID

echo "Shutdown signal received" | tee -a /mnt/host/harness.log
kill $TRACE_PID 2>/dev/null || true
echo "Trace monitor killed" | tee -a /mnt/host/harness.log
sync
echo "Halting..." | tee -a /mnt/host/harness.log
halt -f
