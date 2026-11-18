#!/bin/sh
# guest setup script for nftsim: runs inside the UML guest, loads the ruleset,
# enables tracing, then serves EXEC/SHUTDOWN requests from the host
#
# inputs:
# - /mnt/host/rules.nft - nftables ruleset to load
# - /mnt/host/pre-nft-commands.sh (optional) - commands to run before nft load
# - /mnt/host/post-nft-commands.sh (optional) - commands to run after nft load
# - /mnt/host/host_to_guest.txt - EXEC and SHUTDOWN requests from the host
#
# outputs:
# - /mnt/host/trace.log - nftables trace output
# - /mnt/host/chains.json - base chain hooks
# - /mnt/host/guest_to_host.txt - READY and ACK replies to the host

set -e

# NETLINK_NETFILTER protocol and the NFNLGRP_NFTRACE bit in /proc/net/netlink
NETLINK_NETFILTER=12
NFTRACE_GROUP_MASK=0x100
TRACE_SUBSCRIBE_POLLS=200

# true once some netlink socket has joined the nftables trace group
trace_subscribed() {
  while read -r _sk eth _pid groups _rest; do
    [ "$eth" = "$NETLINK_NETFILTER" ] && [ $((0x$groups & NFTRACE_GROUP_MASK)) -ne 0 ] && return 0
  done < /proc/net/netlink
  return 1
}

echo "nftsim guest setup starting" | tee -a /mnt/host/harness.log

# network interfaces are already configured by the orchestrator

if [ -f /mnt/host/pre-nft-commands.sh ]; then
  echo "running pre-nft commands..." | tee -a /mnt/host/harness.log
  sh /mnt/host/pre-nft-commands.sh
fi

echo "loading nftables ruleset..." | tee -a /mnt/host/harness.log
nft -f /mnt/host/rules.nft
echo "ruleset loaded successfully" | tee -a /mnt/host/harness.log

# record each base chain's hook: traces name the chain, which need not match
# the hook it is attached to (wg-quick's preraw, docker's chains)
nft -j list chains > /mnt/host/chains.json

# chains are discovered at runtime because pre-nft commands may add tables
# that are absent from rules.nft
echo "enabling nftables trace for all chains..." | tee -a /mnt/host/harness.log
nft list tables | while read -r family_table; do
  # "table inet filter" -> family="inet" table="filter"
  family=$(echo "$family_table" | awk '{print $2}')
  table=$(echo "$family_table" | awk '{print $3}')

  if [ -n "$family" ] && [ -n "$table" ]; then
    nft list table "$family" "$table" 2>/dev/null | grep "^\s*chain " | awk '{print $2}' | while read -r chain; do
      if [ -n "$chain" ]; then
        echo "  enabling trace for $family $table $chain"
        nft insert rule "$family" "$table" "$chain" meta nftrace set 1 2>/dev/null || echo "    failed"
      fi
    done
  fi
done

echo "starting nft monitor trace..." | tee -a /mnt/host/harness.log
nft monitor trace > /mnt/host/trace.log &
TRACE_PID=$!
echo "trace monitor PID: $TRACE_PID" | tee -a /mnt/host/harness.log

# the monitor subscribes asynchronously: packets injected before it joins the
# trace group are never traced, so hold READY until it has
polls=0
until trace_subscribed || [ "$polls" -ge "$TRACE_SUBSCRIBE_POLLS" ]; do
  polls=$((polls + 1))
  sleep 0.01
done
if trace_subscribed; then
  echo "trace monitor subscribed after $polls polls" | tee -a /mnt/host/harness.log
else
  echo "warning: trace monitor not subscribed, first packets may go untraced" | tee -a /mnt/host/harness.log
fi

if [ -f /mnt/host/post-nft-commands.sh ]; then
  echo "running post-nft commands..." | tee -a /mnt/host/harness.log
  sh /mnt/host/post-nft-commands.sh
fi

# the host appends requests to host_to_guest.txt over hostfs; poll it and
# handle each new line exactly once, replying with ACK <exit code>
echo "starting command listener..." | tee -a /mnt/host/harness.log

(
  last_line=0
  shutdown_received=0

  while [ "$shutdown_received" -eq 0 ]; do
    if [ -f /mnt/host/host_to_guest.txt ]; then
      current_lines=$(wc -l < /mnt/host/host_to_guest.txt 2>/dev/null || echo 0)

      if [ "$current_lines" -gt "$last_line" ]; then
        line_num=$((last_line + 1))
        while [ "$line_num" -le "$current_lines" ]; do
          line=$(sed -n "${line_num}p" /mnt/host/host_to_guest.txt 2>/dev/null)

          if [ -n "$line" ]; then
            msg_type="${line%% *}"
            msg_data="${line#* }"

            case "$msg_type" in
              EXEC)
                echo "[$(date +%H:%M:%S)] EXEC: $msg_data" >> /mnt/host/commands.log
                eval "$msg_data" >> /mnt/host/commands.log 2>&1
                exit_code=$?
                echo "[$(date +%H:%M:%S)] exit: $exit_code" >> /mnt/host/commands.log
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

    # 10ms keeps host round trips short without spinning the guest CPU
    sleep 0.01
  done
) &
CMD_LISTENER_PID=$!
echo "command listener PID: $CMD_LISTENER_PID" | tee -a /mnt/host/harness.log

echo "guest setup complete, waiting for shutdown signal..." | tee -a /mnt/host/harness.log

echo "READY" >> /mnt/host/guest_to_host.txt
echo "sent READY signal to host" | tee -a /mnt/host/harness.log

# the listener exits only after a SHUTDOWN request
wait $CMD_LISTENER_PID

echo "shutdown signal received" | tee -a /mnt/host/harness.log
kill $TRACE_PID 2>/dev/null || true
echo "trace monitor killed" | tee -a /mnt/host/harness.log
sync
echo "halting..." | tee -a /mnt/host/harness.log
halt -f
