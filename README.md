# Reconnaissance Detection & Analysis Tool

## Acknowledgments

Special thanks to Dr. Karthika Subramani for her mentorship, encouragement, and guidance throughout this research project.


## Description

This project consists of two main components:

1. Zeek Script (recon.zeek)

   * This script runs on Zeek and detects early-stage reconnaissance activity in a network.
   * It generates alerts for:

     * ARP sweeps (Layer 2 host discovery)
     * ICMP sweeps (ping scans)
     * TCP SYN scans:

       * Horizontal scans (one port across many hosts)
       * Vertical scans (many ports on one host)
   * The script logs alerts into Zeek’s notice.log and may also generate a custom syn_rate.log.

2. Python Correlation Script (correlate_zeek_recon.py)

   * This script processes Zeek logs and correlates multiple alerts into meaningful incidents.
   * It groups events by source IP and time window.
   * It classifies activity into categories such as:

     * Multi-stage reconnaissance
     * Horizontal/Vertical scanning
     * Host discovery
   * It can optionally send incidents to an AI model (Cerebras or OpenAI) for deeper analysis.
   * It outputs results in a human-readable format and optionally as JSON.

## Key Features

* Detects multiple reconnaissance techniques
* Correlates events into higher-level incidents
* Uses heuristics to classify attacker behavior
* Optional AI-based analysis for better insights
* Supports both local-only and extended analysis workflows

---

## Prerequisites

Before using this project, make sure you have:

1. Zeek installed

   * https://zeek.org/get-zeek/
   * Required to run the .zeek script and generate logs

2. Python 3.8+

   * Required to run the correlation script

3. Python dependencies (install with pip):
   pip install openai cerebras_cloud_sdk

   Note:

   * These are only required if you plan to use AI analysis
   * The script works without them if AI is disabled

---

How to Use

## Step 1: Run Zeek Script

Run Zeek with the recon script on your network capture:

```
zeek -i <interface> recon.zeek
```

Example:

```
zeek -i eth0 recon.zeek
```

This will generate:

* notice.log
* syn_rate.log (if enabled in your script)

---

## Step 2: Run Python Correlation Script

Basic usage (without AI):

```
python3 correlate_zeek_recon.py notice.log syn_rate.log
```

If you do not have a syn_rate.log:

```
python3 correlate_zeek_recon.py notice.log
```

---

Optional: Enable AI Analysis

Using Cerebras:

```
python3 correlate_zeek_recon.py notice.log syn_rate.log \
    --use-ai --provider cerebras \
    --cerebras-api-key YOUR_API_KEY
```

Using OpenAI:

```
python3 correlate_zeek_recon.py notice.log syn_rate.log \
    --use-ai --provider openai \
    --openai-api-key YOUR_API_KEY
```

---

Optional Arguments

--window <seconds>
Time window for grouping events (default: 300 seconds)

--attach-padding <seconds>
Extra time range when matching SYN rate events (default: 120)

--json-out <file>
Save results to a JSON file

Example:

```
python3 correlate_zeek_recon.py notice.log syn_rate.log \
    --json-out output.json
```

---

## Output

The script prints:

* Incident number
* Source IP
* Time range
* Detected notes (alerts)
* Targets and ports
* Classification label
* Confidence level
* Explanation (rationale)

If AI is enabled:

* Additional AI-generated analysis is included

---

## Summary

This tool helps identify and understand early-stage attacks in a network by:

1. Detecting reconnaissance behavior using Zeek
2. Correlating alerts into meaningful attack patterns
3. Providing automated classification and optional AI insights

It is especially useful for:

* Smart home network monitoring
* Security research
* Intrusion detection analysis

---
