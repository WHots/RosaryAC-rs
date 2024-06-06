# RosaryAC - Proof of Concept Anti-Cheat Client (Work in Progress)

![OIG4 j9lzqjcxld0](https://github.com/WHots/RosaryAC-rs/assets/56490828/e6c34148-1905-42b2-94d8-5961fea42fc0)

## About The Project


RosaryAC is a **proof of concept (PoC)** user-sided anti-cheat client designed to safeguard game processes. This project is currently experimental and under development. The codebase and the project's direction are subject to change at any time.

**Project Change Log**
- **Date:** 5/13/2024
- **Update:** The project has transitioned to an anti-cheat client.

This application is intended as a PoC for those interested in anti-cheat mechanisms. It is important to note that RosaryAC **does not provide resources for reversing cheats** or any malicious methods of gaining undetected access to game client processes. Additionally, it is not designed to target or single out any specific cheat provider.

### Built With

- **Rust Language:** The core of RosaryAC is built using Rust, known for its safety and performance.

### Prerequisites

To work with RosaryAC, you must have Rust and Cargo installed on your system. You can install them using rustup, which is available [here](https://rustup.rs/).

## Anti-Cheat Rules

To maintain fairness and integrity in gameplay, RosaryAC operates under the following rules:

1. **Proof of Malicious Process:**
   - The client **MUST** be able to prove that a malicious process is **running**. Merely having cheat software installed does **NOT** count. It must be proven that the cheat is running at the same time as the game.
   - It also **MUST** be proven that the malicious process is or had interaction with the protected game process.

2. **Memory and Process Interaction:**
   - The client **is NOT** allowed to write into process memory nor interact with system processes during the user-mode stages of this project. This ensures the client operates safely and respects system integrity.

3. **Querying Machine Information:**
   - The client **CAN** query machine information, but **ONLY** during runtime. None of the information queried should be personally identifiable to the user, maintaining user privacy and security.

4. **Network Connections:**
   - The client **is NOT** permitted to create any type of third-party network connection whatsoever. It must not download or upload files, nor fetch any information. The client is designed to operate **100% offline**.

---

**Note:** As this project is a work in progress, the information provided here is subject to change. Keep an eye on the repository for the latest updates. Your contributions and suggestions are welcome to improve RosaryAC. For any issues or feature requests, please refer to the [issues section](#) of the repository.
