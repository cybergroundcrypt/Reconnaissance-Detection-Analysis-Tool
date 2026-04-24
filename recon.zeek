@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn

module SmartHomeRecon;

export {
    redef enum Notice::Type += {
        Port_Scan_Vertical,
        Port_Scan_Horizontal,
        TCP_SYN_Scan_Vertical,
        TCP_SYN_Scan_Horizontal,
        ARP_Sweep,
        ICMP_Sweep
    };

    redef enum Log::ID += { SYN_RATE_LOG };

    type SynRateInfo: record {
        ts: time &log;
        src: addr &log;
        window_start: time &log;
        window_end: time &log;
        syn_count: count &log;
        syn_rate: double &log;
        distinct_targets: count &log;
        distinct_ports: count &log;
        internal_targets: count &log;
        external_targets: count &log;
    };

    const window: interval = 60sec &redef;

    # Connection-based thresholds
    const vertical_ports_thresh: count = 20 &redef;
    const horizontal_hosts_thresh: count = 5 &redef;

    # SYN-based thresholds
    const syn_vertical_ports_thresh: count = 2 &redef;
    const syn_horizontal_hosts_thresh: count = 2 &redef;

    # Sweep thresholds
    const arp_targets_thresh: count = 2 &redef;
    const icmp_targets_thresh: count = 2 &redef;

    # match your LAN, add yours if not here
    const home_nets: set[subnet] = { 192.168.1.0/24, 169.254.0.0/16 } &redef;
}

# ----------------------------------------
# Connection-based scan tracking
# ----------------------------------------
global vertical_seen: table[addr, addr] of set[port] &write_expire=window;
global horizontal_seen: table[addr, port] of set[addr] &write_expire=window;

global vertical_alerted: table[addr, addr] of bool &default=F &write_expire=window;
global horizontal_alerted: table[addr, port] of bool &default=F &write_expire=window;

# ----------------------------------------
# SYN-based TCP scan tracking
# ----------------------------------------
global syn_vertical_seen: table[addr, addr] of set[port] &write_expire=window;
global syn_horizontal_seen: table[addr, port] of set[addr] &write_expire=window;

global syn_vertical_alerted: table[addr, addr] of bool &default=F &write_expire=window;
global syn_horizontal_alerted: table[addr, port] of bool &default=F &write_expire=window;

# ----------------------------------------
# ARP + ICMP sweep tracking
# ----------------------------------------
global arp_seen: table[addr] of set[addr] &write_expire=window;
global icmp_seen: table[addr] of set[addr] &write_expire=window;

global arp_alerted: table[addr] of bool &default=F &write_expire=window;
global icmp_alerted: table[addr] of bool &default=F &write_expire=window;

# ----------------------------------------
# SYN-rate telemetry tracking
# ----------------------------------------
global syn_window_start: table[addr] of time &write_expire=window;
global syn_count_seen: table[addr] of count &default=0 &write_expire=window;
global syn_targets_seen: table[addr] of set[addr] &write_expire=window;
global syn_ports_seen: table[addr] of set[port] &write_expire=window;
global syn_internal_targets_seen: table[addr] of set[addr] &write_expire=window;
global syn_external_targets_seen: table[addr] of set[addr] &write_expire=window;

function in_home(a: addr): bool
    {
    for ( n in home_nets )
        {
        if ( a in n )
            return T;
        }

    return F;
    }

function addr_set_to_string(s: set[addr]): string
    {
    local out = "";
    local first = T;

    for ( a in s )
        {
        if ( !first )
            out = fmt("%s,%s", out, a);
        else
            {
            out = fmt("%s", a);
            first = F;
            }
        }

    return out;
    }

function port_set_to_string(s: set[port]): string
    {
    local out = "";
    local first = T;

    for ( p in s )
        {
        if ( !first )
            out = fmt("%s,%s", out, p);
        else
            {
            out = fmt("%s", p);
            first = F;
            }
        }

    return out;
    }

event zeek_init()
    {
    Log::create_stream(SYN_RATE_LOG,
        [$columns=SynRateInfo, $path="syn_rate"]);
    }

function flush_syn_rate(src: addr)
    {
    if ( src !in syn_window_start )
        return;

    local ws = syn_window_start[src];
    local now_ts = network_time();
    local duration = now_ts - ws;

    if ( duration <= 0secs )
        duration = 1sec;

    local rec: SynRateInfo = [
        $ts=now_ts,
        $src=src,
        $window_start=ws,
        $window_end=now_ts,
        $syn_count=syn_count_seen[src],
        $syn_rate=0.0,
        $distinct_targets=src in syn_targets_seen ? |syn_targets_seen[src]| : 0,
        $distinct_ports=src in syn_ports_seen ? |syn_ports_seen[src]| : 0,
        $internal_targets=src in syn_internal_targets_seen ? |syn_internal_targets_seen[src]| : 0,
        $external_targets=src in syn_external_targets_seen ? |syn_external_targets_seen[src]| : 0
    ];

    rec$syn_rate = syn_count_seen[src] / interval_to_double(duration);

    Log::write(SYN_RATE_LOG, rec);

    delete syn_window_start[src];
    delete syn_count_seen[src];
    delete syn_targets_seen[src];
    delete syn_ports_seen[src];
    delete syn_internal_targets_seen[src];
    delete syn_external_targets_seen[src];
    }

# ----------------------------------------
# Connection-based detector
# Vertical: internal source -> any target
# Horizontal: internal source -> internal target only
# Skips ICMP here so ping sweeps do not overlap
# Skips successful handshakes to reduce false positives
# ----------------------------------------
event connection_state_remove(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dp  = c$id$resp_p;

    if ( !(in_home(src)) )
        return;

    if ( get_port_transport_proto(dp) == icmp )
        return;

    if ( c?$history && /S/ in c$history )
        return;

    # Vertical: internal source -> any destination
    if ( [src, dst] !in vertical_seen )
        vertical_seen[src, dst] = set();

    add vertical_seen[src, dst][dp];

    if ( !vertical_alerted[src, dst] &&
         |vertical_seen[src, dst]| >= vertical_ports_thresh )
        {
        vertical_alerted[src, dst] = T;

        NOTICE([
            $note=Port_Scan_Vertical,
            $msg=fmt("Possible vertical port scan (conn-based): src=%s dst=%s ports=[%s] count=%d window=%s",
                     src, dst,
                     port_set_to_string(vertical_seen[src, dst]),
                     |vertical_seen[src, dst]|,
                     window),
            $identifier=fmt("conn-vscan-%s-%s", src, dst)
        ]);
        }

    # Horizontal: internal source -> internal targets only
    if ( !(in_home(dst)) )
        return;

    if ( [src, dp] !in horizontal_seen )
        horizontal_seen[src, dp] = set();

    add horizontal_seen[src, dp][dst];

    if ( !horizontal_alerted[src, dp] &&
         |horizontal_seen[src, dp]| >= horizontal_hosts_thresh )
        {
        horizontal_alerted[src, dp] = T;

        NOTICE([
            $note=Port_Scan_Horizontal,
            $msg=fmt("Possible horizontal scan (conn-based): src=%s port=%s targets=[%s] count=%d window=%s",
                     src, dp,
                     addr_set_to_string(horizontal_seen[src, dp]),
                     |horizontal_seen[src, dp]|,
                     window),
            $identifier=fmt("conn-hscan-%s-%s", src, dp)
        ]);
        }
    }

# ----------------------------------------
# ARP sweep detector
# internal -> internal only
# ----------------------------------------
event arp_request(mac_src: string, mac_dst: string,
                  spa: addr, sha: string, tpa: addr, tha: string)
    {
    if ( !(in_home(spa)) || !(in_home(tpa)) )
        return;

    if ( spa !in arp_seen )
        arp_seen[spa] = set();

    add arp_seen[spa][tpa];

    if ( !arp_alerted[spa] &&
         |arp_seen[spa]| >= arp_targets_thresh )
        {
        arp_alerted[spa] = T;

        NOTICE([
            $note=ARP_Sweep,
            $msg=fmt("Possible ARP sweep: src=%s targets=[%s] count=%d window=%s",
                     spa,
                     addr_set_to_string(arp_seen[spa]),
                     |arp_seen[spa]|,
                     window),
            $identifier=fmt("arp-sweep-%s", spa)
        ]);
        }
    }

# ----------------------------------------
# Packet-level ICMP + TCP SYN detection
# ----------------------------------------
event raw_packet(p: raw_pkt_hdr)
    {
    # -------------------------
    # ICMP sweep detection
    # internal source -> any destination
    # -------------------------
    if ( p?$ip && p?$icmp )
        {
        local isrc = p$ip$src;
        local idst = p$ip$dst;

        if ( p$icmp$icmp_type == 8 )
            {
            if ( !(in_home(isrc)) )
                return;

            if ( isrc !in icmp_seen )
                icmp_seen[isrc] = set();

            add icmp_seen[isrc][idst];

            if ( !icmp_alerted[isrc] &&
                 |icmp_seen[isrc]| >= icmp_targets_thresh )
                {
                icmp_alerted[isrc] = T;

                NOTICE([
                    $note=ICMP_Sweep,
                    $msg=fmt("Possible ICMP sweep: src=%s targets=[%s] count=%d window=%s",
                             isrc,
                             addr_set_to_string(icmp_seen[isrc]),
                             |icmp_seen[isrc]|,
                             window),
                    $identifier=fmt("icmp-sweep-%s", isrc)
                ]);
                }
            }
        }

    # -------------------------
    # TCP SYN scan detection + SYN-rate telemetry
    # Vertical: internal source -> any destination
    # Horizontal: internal source -> internal targets only
    # -------------------------
    if ( p?$ip && p?$tcp )
        {
        local tsrc = p$ip$src;
        local tdst = p$ip$dst;
        local dp   = p$tcp$dport;
        local flags = p$tcp$flags;

        if ( !(in_home(tsrc)) )
            return;

        if ( (flags & TH_SYN) == 0 )
            return;

        if ( (flags & TH_ACK) != 0 )
            return;

        # SYN-rate telemetry
        if ( tsrc !in syn_window_start )
            {
            syn_window_start[tsrc] = network_time();
            syn_count_seen[tsrc] = 0;
            syn_targets_seen[tsrc] = set();
            syn_ports_seen[tsrc] = set();
            syn_internal_targets_seen[tsrc] = set();
            syn_external_targets_seen[tsrc] = set();
            }

        if ( network_time() - syn_window_start[tsrc] > window )
            {
            flush_syn_rate(tsrc);

            syn_window_start[tsrc] = network_time();
            syn_count_seen[tsrc] = 0;
            syn_targets_seen[tsrc] = set();
            syn_ports_seen[tsrc] = set();
            syn_internal_targets_seen[tsrc] = set();
            syn_external_targets_seen[tsrc] = set();
            }

        syn_count_seen[tsrc] += 1;
        add syn_targets_seen[tsrc][tdst];
        add syn_ports_seen[tsrc][dp];

        if ( in_home(tdst) )
            add syn_internal_targets_seen[tsrc][tdst];
        else
            add syn_external_targets_seen[tsrc][tdst];

        # Vertical: internal source -> any destination
        if ( [tsrc, tdst] !in syn_vertical_seen )
            syn_vertical_seen[tsrc, tdst] = set();

        add syn_vertical_seen[tsrc, tdst][dp];

        if ( !syn_vertical_alerted[tsrc, tdst] &&
             |syn_vertical_seen[tsrc, tdst]| >= syn_vertical_ports_thresh )
            {
            syn_vertical_alerted[tsrc, tdst] = T;

            NOTICE([
                $note=TCP_SYN_Scan_Vertical,
                $msg=fmt("Possible TCP SYN vertical scan: src=%s dst=%s ports=[%s] count=%d window=%s",
                         tsrc, tdst,
                         port_set_to_string(syn_vertical_seen[tsrc, tdst]),
                         |syn_vertical_seen[tsrc, tdst]|,
                         window),
                $identifier=fmt("syn-vscan-%s-%s", tsrc, tdst)
            ]);
            }

        # Horizontal: internal source -> internal targets only
        if ( !(in_home(tdst)) )
            return;

        if ( [tsrc, dp] !in syn_horizontal_seen )
            syn_horizontal_seen[tsrc, dp] = set();

        add syn_horizontal_seen[tsrc, dp][tdst];

        if ( !syn_horizontal_alerted[tsrc, dp] &&
             |syn_horizontal_seen[tsrc, dp]| >= syn_horizontal_hosts_thresh )
            {
            syn_horizontal_alerted[tsrc, dp] = T;

            NOTICE([
                $note=TCP_SYN_Scan_Horizontal,
                $msg=fmt("Possible TCP SYN horizontal scan: src=%s port=%s targets=[%s] count=%d window=%s",
                         tsrc, dp,
                         addr_set_to_string(syn_horizontal_seen[tsrc, dp]),
                         |syn_horizontal_seen[tsrc, dp]|,
                         window),
                $identifier=fmt("syn-hscan-%s-%s", tsrc, dp)
            ]);
            }
        }
    }

event zeek_done()
    {
    for ( src in syn_window_start )
        flush_syn_rate(src);
    }
