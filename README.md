````markdown
# Mock LND gRPC Server

A simplified **mock LND (Lightning Network Daemon) gRPC server** designed to work with wallets like **BlueWallet** and **LNDhub**. This project allows you to test Lightning wallet functionality without running a fully-synced LND node.

This server simulates essential wallet features:  
✅ Creating invoices  
✅ Generating on-chain addresses  
✅ "Paying" invoices  

---

## **What Is This For?**

If you're developing a Lightning wallet or testing BlueWallet features without setting up a real node, this mock server is for you. It acts as a lightweight simulator that you can run locally.

### It allows you to:
- Connect wallets like **BlueWallet** to your mock node.
- Create Bitcoin on-chain addresses for receiving funds.
- Generate Lightning invoices to request payments.
- Simulate invoice payments.
- Maintain a **persistent wallet** (addresses and history survive restarts).

---

## **Features**
- ✅ **Easy Setup**: Run in under 10 minutes.
- 🔑 **Persistent Wallet**: Stores data in `lnd_mock_seed.hex`.
- 📄 **Address Logging**: Saved in `generated_addresses.json`.
- 🔒 **Secure by Default**: Auto-generates TLS certs (`tls.cert`, `tls.key`) and `admin.macaroon`.
- 🔌 **Works with miniBTCD**: Simulates a Bitcoin backend.
- 📱 **BlueWallet Compatible**: Full integration support.

---

## **Installation & Setup**

You will need **two terminal windows** open during setup.

### **Prerequisites**
Install these before starting:
- **Git**: [Download here](https://git-scm.com/downloads)
- **Go**: [Download here](https://go.dev/dl)
- **OpenSSL**:
  - macOS: Pre-installed (`openssl version`)
  - Windows: Install via Git Bash
  - Linux: `sudo apt update && sudo apt install openssl`

---

### **Step 1: Download the Code**
```bash
# Create a folder and navigate into it
mkdir my_lnd_mock
cd my_lnd_mock

# Clone miniBTCD (Bitcoin backend)
git clone https://github.com/Thankgod20/miniBTCD

# Clone LND mock server
git clone https://github.com/Thankgod20/LND-GRPC
````

Now you have:

```
my_lnd_mock/
   ├── miniBTCD
   └── LND-GRPC
```

---

### **Step 2: Run miniBTCD**

```bash
cd miniBTCD
go run .
```

Leave this terminal running.

---

### **Step 3: Run the Mock LND Server**

Open a **new terminal**:

```bash
cd my_lnd_mock/LND-GRPC
go run .
```

On first run, it will generate TLS certs and macaroon:

```
⚠️ TLS certs not found. Generating new ones...
✅ [BakeMacaroon] Successfully generated admin.macaroon
🚀 Mock LND gRPC Server is running securely with TLS on port :10009
```

---

## **Connecting with BlueWallet**

### **1. Find Your Computer's IP**

* macOS: System Settings → Wi-Fi → Details
* Windows: `ipconfig` → Look for "IPv4 Address"

### **2. Get Your admin.macaroon Hex**

```bash
xxd -p -c 1000 admin.macaroon
```

Copy the output (long hex string). Restart the server:

```bash
go run .
```

### **3. Add Wallet in BlueWallet**

Format:

```
lndhub://admin:YOUR_MACAROON_HEX@https://YOUR_IP:10009
```

Example:

```
lndhub://admin:0201036c6e640248...78a5@https://192.168.1.15:10009
```

---

## **Generated Files**

* **tls.cert / tls.key** → TLS encryption files
* **admin.macaroon** → Access credentials
* **lnd\_mock\_seed.hex** → Wallet seed (Do NOT share)
* **lnd\_mock\_state.json** → Tracks address generation
* **generated\_addresses.json** → Logs all addresses

---

## **Advanced Usage**

Connect to a different miniBTCD instance:

```bash
go run . -rpcserver=127.0.0.1:18885
```

---

### ✅ You now have a fully functional **mock LND node** for testing with BlueWallet!


