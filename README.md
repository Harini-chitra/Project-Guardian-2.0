# Project Guardian 2.0 – PII Detector & Redactor

This repository contains the solution for the **Real-time PII Defense** challenge, part of the *Project Guardian 2.0* initiative at Flipkart. The goal of this project is to prevent data leakage by identifying and redacting Personally Identifiable Information (PII) from data streams in real-time.

---

## Challenge Overview

The challenge required developing a system to detect and redact PII from a CSV file containing JSON data. The solution needed to be accurate, efficient, and include a deployment strategy suitable for real-world scenarios.  

Core tasks:

1. **PII Detector & Redactor**: A Python script that processes a CSV file, identifies PII based on definitions, and outputs a new CSV with an `is_pii` flag and redacted data.  
2. **Deployment Strategy**: A proposal for deploying the PII detection solution in a scalable, low-latency, and cost-effective manner.

---

## Solution

The solution is implemented in `detector_full_harinichitra.py`. It uses a **hybrid approach**, combining regular expressions for structured PII and a rule-based system for combinatorial PII.

### Key Features

- **Standalone PII Detection**: Detects phone numbers, Aadhaar card numbers, passport numbers, and UPI IDs using regex.  
- **Combinatorial PII Detection**: Detects PII when two or more of the following appear in the same record: full name, email address, physical address, and device ID/IP address.  
- **Redaction**: Masks identified PII to prevent data leakage (e.g., `[REDACTED_PII]`).  
- **Efficiency**: Designed to process large volumes of data with minimal performance impact.

---

## How to Run

1. **Clone the repository**:

```bash
git clone https://github.com/your-username/Project-Guardian-2.0.git
cd Project-Guardian-2.0

**Run the script with the following command **:

```bash
python3 detector_full_harinichitra.py iscp_pii_dataset_-_Sheet1


## Deployment Strategy

The proposed deployment approach is to integrate the PII detection and redaction logic as a **Sidecar container** in a Kubernetes environment.

### Advantages

- **Scalability**: Sidecar can scale independently of the main application, preventing bottlenecks.  
- **Low Latency**: Running in the same pod ensures minimal network latency.  
- **Ease of Integration**: Can be attached to any application without modifying its codebase.  
- **Cost-Effectiveness**: Eliminates the need for a dedicated PII detection service.

