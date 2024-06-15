# POC_Homomorphic_Firewall

This project is a proof of concept of firewall that use homomorphic encryption to preserve confidentiality during analyze.

# 💻 Install

- `g++` command line
- 🔗 [TFHE library](https://github.com/tfhe/tfhe)

# 🚀 Perform demonstation

> chmod +x emulate.sh

> ./emulate.sh

# 🔦 Working

- > ./client.elf initialize

Create server key and secret key + Encrypt banned IP addresses in a file.

- > ./client.elf analyze

Encrypt network flux to analyze in a file.

- > ./server.elf

Analyzes encrypted network flux by detecting encrypted banned IPs addresses. The result is stored in another file.

- > ./client.elf result

Reads response of the server, and decrypts it to determine if network flux is safe or not.