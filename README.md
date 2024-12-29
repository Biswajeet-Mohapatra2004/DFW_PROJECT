<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReadMe - Anomaly Detection in Network Packets</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f9;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #333;
            color: #fff;
            padding: 20px 0;
            text-align: center;
        }
        header h1 {
            margin: 0;
            font-size: 2rem;
        }
        section {
            padding: 20px;
            margin: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        h2 {
            color: #333;
            font-size: 1.5rem;
        }
        p {
            color: #555;
            line-height: 1.6;
        }
        ul {
            margin: 10px 0;
            padding: 0 20px;
            color: #555;
        }
        ul li {
            margin-bottom: 10px;
        }
        .code-block {
            background: #f0f0f0;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <header>
        <h1>Anomaly Detection in Network Packets</h1>
    </header>
    <section>
        <h2>Project Overview</h2>
        <p>
            This project provides a Python-based solution to analyze and detect anomalies in network traffic from a PCAP file using Scapy. 
            It implements rule-based detection mechanisms to identify suspicious activities, generate insights, and report them in a structured CSV file.
        </p>
    </section>
    <section>
        <h2>Features</h2>
        <ul>
            <li>Detection of traffic using non-standard TCP/UDP ports.</li>
            <li>Identification of excessive traffic indicative of DDoS attacks.</li>
            <li>Packet size analysis to flag oversized packets exceeding MTU.</li>
            <li>Detection of unsolicited ARP replies and large DNS responses.</li>
            <li>Monitoring for excessive ICMP Echo requests.</li>
            <li>Identification of TCP SYN floods and port scanning attempts.</li>
        </ul>
    </section>
    <section>
        <h2>Generated Report</h2>
        <p>
            The project generates a <code>report.csv</code> file with the following columns:
        </p>
        <ul>
            <li><strong>IP Address</strong> and <strong>MAC Address</strong>: Identifies the devices.</li>
            <li>Columns for each rule: Values indicate whether the rule was violated (1 for yes, 0 for no).</li>
            <li><strong>MDP (%):</strong> Malicious Device Probability, calculated as the percentage of violated rules.</li>
        </ul>
        <div class="code-block">
            Example: <br>
            IP Address, MAC Address, Rule1, Rule2, ..., Rule8, MDP<br>
            192.168.0.1, 00:1A:2B:3C:4D:5E, 1, 0, 1, 0, ..., 0, 25%
        </div>
    </section>
    <section>
        <h2>Technology Stack</h2>
        <ul>
            <li><strong>Python</strong>: For network packet analysis and rule-based detection.</li>
            <li><strong>Scapy</strong>: A Python library for packet manipulation and analysis.</li>
            <li><strong>CSV</strong>: For structured reporting.</li>
        </ul>
    </section>
    <section>
        <h2>How to Run</h2>
        <ul>
            <li>Install the required Python dependencies.</li>
            <li>Place the target PCAP file in the project directory.</li>
            <li>Run the script using: <code>python anomaly_detection.py</code></li>
            <li>Check the generated <code>report.csv</code> for the analysis results.</li>
        </ul>
    </section>
</body>
</html>
