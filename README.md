# LND gRPC Server

A simplified LND (Lightning Network Daemon) gRPC server designed to work with wallets and LNDhub. This project allows you to test Lightning wallet functionality without running a fully-synced LND node.

This server simulates essential wallet features: creating invoices, generating on-chain addresses, and paying invoices.

What Is This For?

If you're developing a Lightning wallet or testing  features without setting up a real node, this mock server is for you. It acts as a lightweight simulator that you can run locally.

It allows you to:

* Connect wallets like BlueWallet to your mock node
* Create Bitcoin on-chain addresses for receiving funds
* Generate Lightning invoices to request payments
* Simulate invoice payments
* Maintain a persistent wallet (addresses and history survive restarts)

Features:

* Easy Setup: Run in under 10 minutes
* Persistent Wallet: Stores data in lnd\_mock\_seed.hex
* Address Logging: Saved in generated\_addresses.json
* Secure by Default: Auto-generates TLS certs (tls.cert, tls.key) and admin.macaroon
* Works with miniBTCD: Simulates a Bitcoin backend


Installation & Setup:

You will need two terminal windows open during setup.

Prerequisites:

* Git
* Go
* OpenSSL (macOS pre-installed, install on Windows via Git Bash, Linux with apt install)

Step 1: Download the Code

```
mkdir my_lnd
cd my_lnd
git clone https://github.com/Thankgod20/miniBTCD
git clone https://github.com/Thankgod20/LND-GRPC
```

Step 2: Run miniBTCD

```
check the documentation
```

Step 3: Run the LND Server
Open a new terminal:

```
cd my_lnd/LND-GRPC
go run .
```

First run will generate TLS certs and macaroon.

Connecting with BlueWallet:

1. Find your computer’s IP (macOS: System Settings → Wi-Fi, Windows: ipconfig)
2. Get your admin.macaroon hex:

```
xxd -p -c 1000 admin.macaroon
```

Copy the string and restart server:

```
go run .
```

3. Add to wallet:

```
http://ip:3000
```

Generated Files:

* tls.cert / tls.key – TLS encryption files
* admin.macaroon – Access credentials
* lnd\_mock\_seed.hex – Wallet seed
* lnd\_mock\_state.json – Tracks address generation
* generated\_addresses.json – Logs all addresses

Advanced Usage:
Connect to a different miniBTCD instance:

```
go run . -rpcserver=127.0.0.1:18885
```

You now have a fully functional mock LND node for testing with BlueWallet.
