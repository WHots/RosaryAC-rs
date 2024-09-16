# RosaryEDR - Proof of Concept User Mode EDR / Threat Detection System (Work in Progress)

![d6d6a16a-4623-4c71-8b85-520fc1cf37fe](https://github.com/user-attachments/assets/eb7d84bf-ecc4-430f-a090-49717ba9427c)

## About The Project

RosaryEDR is a **proof of concept (PoC)** user mode Endpoint Detection and Response (EDR) / Threat Detection System designed to identify and report suspicious activities on endpoints. This project is currently experimental and under development. The codebase and the project's direction are subject to change at any time.

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

## EDR Rules

To maintain system security and integrity, RosaryEDR operates under the following rules:

1. **Proof of Malicious Process:**
   - The system **MUST** be able to prove that a malicious process is **running**. Merely having potentially harmful software installed does **NOT** count. It must be proven that the threat is active at the time of detection.
   - It also **MUST** be proven that the malicious process is or had interaction with the protected system processes.

2. **Memory and Process Interaction:**
   - The system **is NOT** allowed to write into process memory nor interact with system processes during the user-mode stages of this project. This ensures the system operates safely and respects system integrity.

3. **Querying Machine Information:**
   - The system **CAN** query machine information, but **ONLY** during runtime. None of the information queried should be personally identifiable to the user, maintaining user privacy and security.

4. **Network Connections:**
   - The system **is NOT** permitted to create any type of third-party network connection whatsoever. It must not download or upload files, nor fetch any information. The system is designed to operate **100% offline**.

---

**Note:** As this project is a work in progress, the information provided here is subject to change. Keep an eye on the repository for the latest updates. Your contributions and suggestions are welcome to improve RosaryEDR. For any issues or feature requests, please refer to the [issues section](#).
