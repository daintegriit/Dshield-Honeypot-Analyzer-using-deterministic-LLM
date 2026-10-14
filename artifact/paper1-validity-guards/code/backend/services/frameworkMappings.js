/**
 * frameworkMappings.js
 * ----------------------------------------
 * Purpose:
 * - Deterministically map observed behavior to
 *   MITRE ATT&CK, NIST CSF, CIS Controls, and SOC semantics
 * - Serve as the ONLY source of truth for framework alignment
 * - Feed Copilot explanations WITHOUT allowing speculation
 *
  * Design Principles:
  * - Explicit mappings only: no fuzzy logic or guesswork
  * - Analyst-friendly labels and descriptions
  * - Clear confidence drivers for each category
  * - Modular structure for easy updates and expansions
  * 
  * use case: when an attack pattern is detected, reference this mapping to:
  * 1) Tag the event with relevant MITRE, NIST, CIS categories
  * 2) Generate a human-readable label and description for SOC analysts
  * 3) Provide clear confidence drivers to explain why this classification was made
  * 4) Ensure Copilot's explanations are grounded in these mappings, avoiding any speculation or overreach 
  * 
  * 
 */

module.exports = {
  /* ======================================================
     AUTHENTICATION & ACCESS ABUSE
  ====================================================== */
  AUTH_BRUTE_FORCE: {
    label: "Authentication Brute Force / Credential Abuse",

    description:
      "Repeated authentication attempts against exposed services indicating credential guessing or stuffing behavior.",

    ports: [22, 23, 3389, 5900, 2222],

    mitre: [
      {
        id: "T1110",
        name: "Brute Force",
        tactics: ["Credential Access"],
      },
    ],

    nist: [
      {
        id: "PR.AC-1",
        name: "Identities and credentials are managed",
      },
      {
        id: "PR.AC-7",
        name: "Users are authenticated",
      },
      {
        id: "DE.CM-7",
        name: "Monitoring for unauthorized access",
      },
    ],

    cis: [
      {
        id: "CIS-5",
        name: "Account Management",
      },
      {
        id: "CIS-6",
        name: "Access Control Management",
      },
    ],

    socMeaning:
      "Indicates attempts to gain unauthorized access through credential misuse. Often precedes lateral movement or privilege escalation.",

    confidenceDrivers: [
      "High event concentration on auth ports",
      "Low port entropy",
      "Repeated source IPs",
    ],
  },

  /* ======================================================
     NETWORK SCANNING & RECONNAISSANCE
  ====================================================== */
  NETWORK_RECON: {
    label: "Network Reconnaissance / Port Scanning",

    description:
      "Broad or targeted probing of multiple services to identify exposed attack surfaces.",

    ports: "ANY",

    mitre: [
      {
        id: "T1046",
        name: "Network Service Scanning",
        tactics: ["Discovery"],
      },
    ],

    nist: [
      {
        id: "DE.CM-7",
        name: "Monitoring for unauthorized network activity",
      },
      {
        id: "PR.PT-1",
        name: "Audit/log records are generated",
      },
    ],

    cis: [
      {
        id: "CIS-13",
        name: "Network Monitoring and Defense",
      },
    ],

    socMeaning:
      "Typically represents early-stage attack lifecycle activity. May be opportunistic or preparatory.",

    confidenceDrivers: [
      "High distinct port count",
      "Short time window",
      "Elevated scan score",
    ],
  },

  /* ======================================================
     WEB APPLICATION EXPLOITATION
  ====================================================== */
  WEB_EXPLOITATION: {
    label: "Web Application Exploitation",

    description:
      "Attempts to exploit vulnerabilities in public-facing web services or APIs.",

    ports: [80, 443, 8080, 8443],

    mitre: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactics: ["Initial Access"],
      },
    ],

    nist: [
      {
        id: "PR.IP-1",
        name: "Configuration management processes",
      },
      {
        id: "DE.CM-7",
        name: "Monitoring for malicious activity",
      },
    ],

    cis: [
      {
        id: "CIS-16",
        name: "Application Software Security",
      },
    ],

    socMeaning:
      "Indicates direct attempts to exploit application-layer vulnerabilities. Risk increases if paired with anomalous payloads.",

    confidenceDrivers: [
      "Sustained traffic to web ports",
      "Concentration from limited ASNs",
      "Repetitive request patterns",
    ],
  },

  /* ======================================================
     LATERAL MOVEMENT & INTERNAL EXPANSION
  ====================================================== */
  LATERAL_MOVEMENT: {
    label: "Lateral Movement / Internal Expansion",

    description:
      "Attempts to move within the environment after initial access.",

    ports: [445, 139, 3389],

    mitre: [
      {
        id: "T1021",
        name: "Remote Services",
        tactics: ["Lateral Movement"],
      },
    ],

    nist: [
      {
        id: "PR.AC-5",
        name: "Network integrity protection",
      },
      {
        id: "DE.CM-7",
        name: "Monitoring for unauthorized movement",
      },
    ],

    cis: [
      {
        id: "CIS-13",
        name: "Network Monitoring",
      },
      {
        id: "CIS-8",
        name: "Audit Log Management",
      },
    ],

    socMeaning:
      "More advanced attack stage. Often follows credential compromise or service exploitation.",

    confidenceDrivers: [
      "Repeated internal service targeting",
      "Consistent source IP reuse",
      "Service-specific focus",
    ],
  },

  /* ======================================================
     DENIAL-OF-SERVICE / FLOODING
  ====================================================== */
  TRAFFIC_FLOOD: {
    label: "Traffic Flood / Denial of Service",

    description:
      "High-volume traffic intended to overwhelm services or obscure other activity.",

    ports: "ANY",

    mitre: [
      {
        id: "T1498",
        name: "Network Denial of Service",
        tactics: ["Impact"],
      },
    ],

    nist: [
      {
        id: "PR.PT-4",
        name: "Communications and control networks protected",
      },
      {
        id: "DE.CM-1",
        name: "Anomalies detected",
      },
    ],

    cis: [
      {
        id: "CIS-13",
        name: "Network Monitoring and Defense",
      },
    ],

    socMeaning:
      "Can indicate service disruption attempts or diversionary noise masking other intrusions.",

    confidenceDrivers: [
      "High burst ratio",
      "Large traffic volume",
      "Low source diversity",
    ],
  },

  /* ======================================================
     UNKNOWN / AMBIGUOUS ACTIVITY
  ====================================================== */
  UNCLASSIFIED_ACTIVITY: {
    label: "Unclassified or Ambiguous Activity",

    description:
      "Observed behavior does not strongly match a known attack pattern.",

    ports: "ANY",

    mitre: [],
    nist: [],
    cis: [],

    socMeaning:
      "Requires analyst review. Insufficient evidence for confident classification.",

    confidenceDrivers: [
      "Low signal strength",
      "Sparse data",
      "Conflicting indicators",
    ],
  },
};