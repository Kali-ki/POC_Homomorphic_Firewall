# POC_Homomorphic_Firewall

This project is a proof of concept of firewall that use homomorphic encryption to preserve confidentiality during analyze.

# 💻 Install

- `g++` command line
- 🔗 [TFHE library](https://github.com/tfhe/tfhe?tab=readme-ov-file#installation)

# 📄 Important files

- 📘 Networkflow to analyze : `networkflow.txt`

- 📃 IP addresses to ban : `banned_ip.txt`

# 🚀 Perform demonstation

> chmod +x emulate.sh

> ./emulate.sh

# 🔦 Working

## Compiling

> g++ client.cpp utils.cpp -o client.elf -ltfhe-spqlios-fma

> g++ server.cpp utils.cpp -o server.elf -ltfhe-spqlios-fma

## Execute

- > ./client.elf initialize

Create server key and secret key + Encrypt banned IP (banned_ip.txt) addresses in a file (banned_ip.data).

- > ./client.elf analyze

Encrypt network flux (networkflow.txt) to analyze in a file (ip_to_analyze.data).

- > ./server.elf

Analyzes encrypted network flux by detecting encrypted banned IPs addresses. The result is stored in another file (answer.data).

- > ./client.elf result

Reads response of the server, and decrypts it to determine if network flux is safe or not.
