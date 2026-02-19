// utils/categorizeAttack.js

module.exports = function categorizeAttack(port, protocol = "TCP") {
    // If protocol is ICMP (proto 1)
    if (protocol && protocol.toUpperCase() === "ICMP") {
        return "ICMP Probe";
    }

    if (!port) return "Unknown";

    // Normalize
    port = Number(port);

    // --- High-Signal Security Ports ---
    if (port === 22) return "SSH Brute Force";
    if (port === 23) return "Telnet Attack";
    if (port === 443) return "HTTPS Scan";
    if (port === 80) return "HTTP Scan";
    if (port === 25) return "SMTP Abuse / Spam Attempt";
    if (port === 21) return "FTP Attack";
    if (port === 3306) return "MySQL Scan";
    if (port === 3389) return "RDP Attack";
    if (port === 5432) return "Postgres Scan";
    if (port === 6379) return "Redis Exploit Attempt";
    if (port === 27017) return "MongoDB Scan";

    // --- Common Malware / Botnet Ports ---
    if (port === 8080) return "Proxy / Botnet Traffic";
    if (port === 4444) return "Metasploit / RAT Traffic";
    if (port === 1337) return "Botnet C2";
    if (port === 1900) return "SSDP Amplification (DDoS)";
    if (port === 123) return "NTP Amplification (DDoS)";
    if (port === 53) return "DNS Attack / DNS Amplification";

    // --- Registered Ports ---
    if (port >= 1024 && port <= 49151) return "General Scan";

    // --- Ephemeral Ports ---
    if (port >= 49152) return "High-Port Probe";

    return "Unknown";
};