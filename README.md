# Post-Quantum Cryptography (PQC) Secure Communication

## Overview
This project focuses on implementing and evaluating **Post-Quantum Cryptographic (PQC) protocols** for secure client-server communication. With the advancement of quantum computing, conventional encryption schemes such as RSA and ECC are at risk of being broken, making it essential to explore quantum-resistant alternatives.

The project integrates and tests multiple approaches, including **XOR combined with PQC, AES combined with PQC, and hybrid cryptographic models**. These implementations are benchmarked to analyze performance factors such as latency, throughput, and resource usage, with the aim of identifying the most effective approach for practical deployment.

Developed in **C with the liboqs library**, the project provides a lightweight framework for secure communication resistant to quantum-based threats. The ultimate goal is to contribute to the growing body of research on **quantum-safe cryptography** and to provide foundations for applications such as secure messaging, VPNs, and credential protection in the post-quantum era.

---

## Features
- Implementation of XOR+PQC, AES+PQC, and Hybrid cryptographic models  
- Benchmarking and comparison of different approaches  
- Secure client-server communication framework  
- Integration with the [liboqs](https://github.com/open-quantum-safe/liboqs) library  
