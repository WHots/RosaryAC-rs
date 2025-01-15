# RosaryEDR - Proof of Concept User Mode EDR / Threat Detection System (Work in Progress)

## About The Project
RosaryEDR is a **proof of concept (PoC)** user mode Endpoint Detection and Response (EDR) / Threat Detection System designed to identify and report suspicious activities on endpoints. This project is experimental and focuses solely on threat detection and notification, without active threat elimination.

**Project Change Log**
- **Date:** 8/6/2024
- **Update:** The project has transitioned to a user-mode EDR / Threat Detection System.
- **Date:** ~~5/13/2024~~
- **Update:** ~~The project has transitioned to an Anti-Cheat user client.~~

This application is intended as a PoC for those interested in endpoint security mechanisms. It is important to note that RosaryEDR **does not provide resources for executing or reversing malicious activities**. Additionally, it is not designed to target or single out any specific threat actor.

### Built With
- **Rust Language:** The core of RosaryEDR is built using Rust, known for its safety and performance.

### Prerequisites
To work with RosaryEDR, you must have Rust and Cargo installed on your system. You can install them using rustup, which is available [here](https://rustup.rs/).

## EDR Rules and Limitations

### Core Operational Rules
1. **Detection Only Mode:**
   - The system operates in a **detection-only** mode
   - Will NOT attempt to eliminate or neutralize threats
   - Only provides notification and documentation of detected threats

2. **System Interaction Restrictions:**
   - CANNOT interact with system processes
   - CANNOT write into process memory
   - CANNOT modify any system settings or configurations

3. **Network Restrictions:**
   - Operates 100% offline
   - NO third-party network connections
   - NO downloading or uploading of files
   - NO external data fetching

4. **File System Operations:**
   - CAN create its own directories and files
   - CAN only write to files/directories it has created
   - CANNOT modify any existing system files

### Threat Detection Requirements
1. **Evidence Requirements:**
   - Must provide concrete proof of active threats
   - Must document interactions with protected processes
   - Static presence of potentially harmful software is NOT sufficient for alert

2. **Documentation Required:**
   - Must capture screen evidence of detected threats
   - Must create a detailed snapshot of threat characteristics
   - Must maintain logs of detection events

### Privacy and Security
1. **Information Gathering:**
   - Only collects runtime information
   - NO collection of personally identifiable information
   - NO persistent tracking of user activities

2. **Data Storage:**
   - All data stored locally
   - NO cloud storage or transmission
   - Only stores information relevant to threat detection

---

**Note:** As this project is a work in progress, these rules and requirements may be subject to refinement. The focus remains on creating a secure, privacy-respecting threat detection system that operates within strict ethical boundaries.

For any issues or feature requests, please refer to the [issues section](#).
