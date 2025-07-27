// LND-GRPC/main.go
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/reflection"

	"github.com/Thankgod20/miniBTCD/blockchain"
	"github.com/Thankgod20/miniBTCD/trx"
	"github.com/btcsuite/btcd/btcec/v2"
	ecdsa_ "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"golang.org/x/crypto/ripemd160"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

// We need a simple proto definition for our new Debug service.
// Normally this would be in a .proto file, but for simplicity, we define it here.
// This part is just for our internal use and doesn't affect LND compatibility.

// --- mockLndServer (Implements Lightning and Invoices services) ---
type mockLndServer struct {
	lnrpc.UnimplementedLightningServer
	invoicesrpc.UnimplementedInvoicesServer

	mu              sync.RWMutex
	invoices        map[string]*lnrpc.Invoice
	invoiceChan     chan *lnrpc.Invoice
	macaroonRootKey []byte
	nodePrivateKey  *btcec.PrivateKey
	nodePublicKey   *btcec.PublicKey
	client          *rpc.Client       // For miniBTCD RPC client
	seed            map[string][]byte // For generating addresses
	nextIndex       map[string]uint32 // For generating addresses
}

// --- mockRouterServer (For resolving method ambiguity) ---
type mockRouterServer struct {
	routerrpc.UnimplementedRouterServer
	mainServer *mockLndServer
}
type AddressRecord struct {
	NextIndex uint32 `json:"nextIndex"`
	Address   string `json:"address"`
	CreatedAt string `json:"createdAt"`
}

const seedFileName = "lnd_mock_seed.hex"
const stateFileName = "lnd_mock_state.json"
const addressesFileName = "generated_addresses.json"

// NewMockLndServer creates and initializes our mock server.
func NewMockLndServer(rpcServerAddr string) *mockLndServer {
	log.Println("🌱 Initializing mock LND server... using RPC Server", rpcServerAddr)
	rootKey := make([]byte, 32)
	rand.Read(rootKey)
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	client, err := rpc.Dial("tcp", rpcServerAddr)
	if err != nil {
		log.Fatalf("Failed to connect to RPC server: %v", err)
	}
	var seed []byte

	seedHex, err := ioutil.ReadFile(seedFileName)
	if err != nil {
		// If the file doesn't exist, we need to create a new seed.
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("🌱 No seed file found. Generating a new persistent seed at '%s'", seedFileName)

			// Generate a new random seed.
			newSeed := make([]byte, 32)
			if _, err := rand.Read(newSeed); err != nil {
				return nil
			}

			// Save the new seed to the file as a hex string.
			err = ioutil.WriteFile(seedFileName, []byte(hex.EncodeToString(newSeed)), 0644)
			if err != nil {
				return nil
			}

			// Use the new seed for this session.
			seed = newSeed

		} else {
			// Any other error reading the file is a fatal problem.
			return nil
		}
	} else {
		// If the file was read successfully, decode the hex back into bytes.
		log.Printf("🌱 Found persistent seed file. Loading wallet.")
		seed, err = hex.DecodeString(string(seedHex))
		if err != nil {
			return nil
		}
	}
	// --- Part 2: Load or Create the Persistent STATE (nextIndex) ---
	var nextIndex map[string]uint32

	stateJSON, err := ioutil.ReadFile(stateFileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("🌱 No state file found. Initializing new state at '%s'", stateFileName)
			// If no state file, start with a fresh index map.
			nextIndex = map[string]uint32{
				"default": 0,
			}

		} else {
			return nil
		}
	} else {
		log.Printf("🌱 Found persistent state file. Loading last known index.")
		// If file exists, unmarshal the JSON into our map.
		err = json.Unmarshal(stateJSON, &nextIndex)
		if err != nil {
			return nil
		}
	}
	//rand.Read(seed)
	seeds := map[string][]byte{
		"default": seed, // the seed you already made
	}

	return &mockLndServer{
		invoices:        make(map[string]*lnrpc.Invoice),
		invoiceChan:     make(chan *lnrpc.Invoice, 100),
		macaroonRootKey: rootKey,
		nodePrivateKey:  privKey,
		nodePublicKey:   privKey.PubKey(),
		client:          client,

		seed:      seeds,
		nextIndex: nextIndex,
	}
}

// --- Lightning Service Implementation ---

// BakeMacaroon now correctly implements the method from the lnrpc.LightningServer interface.
func (s *mockLndServer) BakeMacaroon(ctx context.Context, req *lnrpc.BakeMacaroonRequest) (*lnrpc.BakeMacaroonResponse, error) {
	log.Println("✅ [BakeMacaroon] Called")

	// Create a new macaroon with our server's secret root key.
	// CORRECT VERSION
	// Create a byte slice to hold the 8 bytes of the uint64.
	idBytes := make([]byte, 8)
	// Use binary.BigEndian to write the integer into the byte slice.
	binary.BigEndian.PutUint64(idBytes, req.RootKeyId)

	mac, err := macaroon.New(
		s.macaroonRootKey,
		idBytes, // <-- NOW PASSING THE CORRECT TYPE
		"lnd",
		macaroon.V2,
	)
	if err != nil {
		return nil, err
	}

	// Add caveats (permissions) from the request.
	for _, p := range req.Permissions {
		if err := mac.AddFirstPartyCaveat(
			[]byte(fmt.Sprintf("permissions = %s:%s", p.Entity, p.Action)),
		); err != nil {
			return nil, err
		}
	}

	macBytes, err := mac.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// For our purposes, we'll just write it to a well-known file.
	err = ioutil.WriteFile("admin.macaroon", macBytes, 0644)
	if err != nil {
		log.Printf("❌ [BakeMacaroon] Failed to write macaroon file: %v", err)
		return nil, err
	}
	log.Println("✅ [BakeMacaroon] Successfully generated and saved admin.macaroon")

	// The real RPC returns the macaroon as a hex string.
	macHex := hex.EncodeToString(macBytes)
	return &lnrpc.BakeMacaroonResponse{Macaroon: macHex}, nil
}

// --- Lightning Service Implementation (on mockLndServer) ---

func (s *mockLndServer) GetInfo(ctx context.Context, in *lnrpc.GetInfoRequest) (*lnrpc.GetInfoResponse, error) {
	log.Println("✅ [GetInfo] Called")
	return &lnrpc.GetInfoResponse{
		Version: "lnd-grpc-mock-v2.0-final",
		//IdentityPubkey: "03mockidentitypubkey123456789012345678901234567890123456789012345",
		IdentityPubkey: hex.EncodeToString(s.nodePrivateKey.PubKey().SerializeCompressed()),
		Alias:          "My Mock LND Node",
		BlockHeight:    800000,
		SyncedToChain:  true,
		SyncedToGraph:  true,
	}, nil
}
func (s *mockLndServer) ListChannels(ctx context.Context, in *lnrpc.ListChannelsRequest) (*lnrpc.ListChannelsResponse, error) {
	log.Println("✅ [ListChannels] Called")
	// Return an empty list for now
	return &lnrpc.ListChannelsResponse{
		Channels: []*lnrpc.Channel{},
	}, nil
}

// ListInvoices returns a list of all invoices. LNDhub uses this to
// reconcile the user's off-chain balance.
func (s *mockLndServer) ListInvoices(ctx context.Context, req *lnrpc.ListInvoiceRequest) (*lnrpc.ListInvoiceResponse, error) {
	log.Println("✅ [ListInvoices] Called")
	s.mu.RLock()
	defer s.mu.RUnlock()

	var invoices []*lnrpc.Invoice
	for _, inv := range s.invoices {
		// Real LND would have filtering logic here based on the request.
		// For our purpose, returning all is fine.
		invoices = append(invoices, inv)
	}

	log.Printf("📝 [ListInvoices] Returning %d invoices.", len(invoices))
	return &lnrpc.ListInvoiceResponse{
		Invoices: invoices,
	}, nil
}

/*
func (s *mockLndServer) GetTransactions(ctx context.Context, req *lnrpc.GetTransactionsRequest) (*lnrpc.TransactionDetails, error) {
	log.Println("GetTransactions called", req.Account)

	// Example: BlueWallet wants all transactions for the wallet
	// We assume a single address wallet for now
	account := req.Account
	if account == "" {
		account = "default"
	}
	seed := s.seed[account]
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	// m/84'/1'/0'/0
	purpose, err := master.Child(hdkeychain.HardenedKeyStart + 84)
	if err != nil {
		return nil, err
	}
	coin, err := purpose.Child(hdkeychain.HardenedKeyStart + 1)
	if err != nil {
		return nil, err
	}
	acct, err := coin.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, err
	}
	ext, err := acct.Child(0)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, 20)
	for i := uint32(0); i < 20; i++ {
		child, err := ext.Child(i)
		if err != nil {
			return nil, err
		}
		pub, err := child.ECPubKey()
		if err != nil {
			return nil, err
		}
		addr, err := bech32Address("bc", pub.SerializeCompressed())
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	address := "bc1qtmzscqkd59dfjuv3fpleutllpz5pvrv2vczfru"
	log.Println("[]All address:", addrs)
	// First get transaction hashes from address history
	args := blockchain.GetAddressHistoryArgs{Address: address}
	var historyReply blockchain.GetAddressHistoryReply
	err = s.client.Call("Blockchain.GetTransactionHistory", &args, &historyReply)
	if err != nil {
		return nil, fmt.Errorf("failed to get address history: %v", err)
	}

	var transactions []*lnrpc.Transaction

	for _, txid := range historyReply.TransactionHex {
		// Now fetch full transaction details
		fullArgs := blockchain.GetVerifyTransactionArgs{TransactionID: txid}
		var fullReply blockchain.GetLatestBlockReply

		err := s.client.Call("Blockchain.GetFulTXElect", &fullArgs, &fullReply)
		if err != nil {
			log.Printf("Failed to fetch full transaction for %s: %v", txid, err)
			continue
		}

		// Parse the JSON response
		var fullTx struct {
			BlockHash     string `json:"blockhash"`
			BlockTime     int64  `json:"blocktime"`
			Confirmations int64  `json:"confirmations"`
			Hash          string `json:"hash"`
			Hex           string `json:"transactionHex"`
			Height        int32  `json:"height"`
			Time          int64  `json:"time"`
			Vout          []struct {
				Value        float64 `json:"value"`
				ScriptPubKey struct {
					Addresses []string `json:"addresses"`
				} `json:"scriptPubKey"`
			} `json:"vout"`
		}

		if err := json.Unmarshal([]byte(fullReply.JSONString), &fullTx); err != nil {
			log.Printf("Failed to decode transaction JSON for %s: %v", txid, err)
			continue
		}
		rawBytes, err := hex.DecodeString(fullTx.Hex)
		if err != nil {
			log.Printf("❌ invalid hex for %s: %v", txid, err)
			continue
		}
		if !isSegWitTransaction(rawBytes) {
			log.Printf("❌ transaction %s is not a SegWit transaction, skipping", txid)
			continue
		}
		// Compute amount for the wallet (sum outputs to our address)
		var amount int64
		for _, out := range fullTx.Vout {
			for _, addr := range out.ScriptPubKey.Addresses {
				if addr == address {
					amount += int64(out.Value * 1e8) // Convert BTC → sats
				}
			}
		}
		//fmt.Println("Transaction amount for address", address, "is", amount, "sats", "fullTx", fullTx)
		transactions = append(transactions, &lnrpc.Transaction{
			TxHash:           fullTx.Hash,
			Amount:           amount,
			NumConfirmations: int32(fullTx.Confirmations),
			BlockHash:        fullTx.BlockHash,
			BlockHeight:      fullTx.Height,
			TimeStamp:        fullTx.Time,
			RawTxHex:         fullTx.Hex,
		})
	}
	fmt.Println("Transaction amount for address", address, "is", transactions)
	return &lnrpc.TransactionDetails{Transactions: transactions}, nil
}
*/
/*
func (s *mockLndServer) GetTransactions(ctx context.Context, req *lnrpc.GetTransactionsRequest) (*lnrpc.TransactionDetails, error) {
	log.Println("✅ [GetTransactions] called for account:", req.Account)

	// 1. Setup: Determine account and get the correct seed.
	account := req.Account
	if account == "" {
		account = "default"
	}
	seed, ok := s.seed[account]
	if !ok {
		return nil, fmt.Errorf("account not found: %s", account)
	}

	s.mu.RLock()
	currentIndex := s.nextIndex[account]
	s.mu.RUnlock()

	// 2. Address Discovery: Generate all addresses for this wallet up to the current index + a gap limit.
	// The gap limit ensures we find transactions even if some addresses were generated but never used.
	const gapLimit = 20
	scanUpto := currentIndex + gapLimit
	walletAddresses := make(map[string]bool) // Use a map for efficient lookups

	log.Printf("🔍 [GetTransactions] Discovering addresses for account '%s' up to index %d", account, scanUpto-1)

	// Derive the master key and the external chain key once.
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	// Path: m/84'/0'/0'/0
	purpose, _ := master.Child(hdkeychain.HardenedKeyStart + 84)
	coin, _ := purpose.Child(hdkeychain.HardenedKeyStart + 0)
	acct, _ := coin.Child(hdkeychain.HardenedKeyStart + 0)
	ext, _ := acct.Child(0)

	for i := uint32(0); i < scanUpto; i++ {
		child, err := ext.Child(i)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key at index %d: %w", i, err)
		}
		pub, err := child.ECPubKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get pubkey at index %d: %w", i, err)
		}
		// Using your existing bech32Address helper, which is correct.
		addr, err := bech32Address("bc", pub.SerializeCompressed())
		if err != nil {
			return nil, fmt.Errorf("failed to generate bech32 address at index %d: %w", i, err)
		}
		walletAddresses[addr] = true
	}
	log.Printf("🔍 [GetTransactions] Discovered %v addresses for wallet.", (walletAddresses))

	// 3. Fetch History for all Addresses: Collect all unique transaction IDs.
	uniqueTxIDs := make(map[string]struct{})
	for addr := range walletAddresses {
		args := blockchain.GetAddressHistoryArgs{Address: addr}
		var historyReply blockchain.GetAddressHistoryReply
		err := s.client.Call("Blockchain.GetTransactionHistory", &args, &historyReply)
		if err != nil {
			// Log error but continue, one address might fail or have no history
			log.Printf("⚠️  Could not get history for address %s: %v", addr, err)
			continue
		}
		for _, txid := range historyReply.TransactionHex {
			uniqueTxIDs[txid] = struct{}{}
		}
	}
	log.Printf("🔍 [GetTransactions] Found %d unique transactions across all addresses.", len(uniqueTxIDs))

	// 4. Process Unique Transactions
	var transactions []*lnrpc.Transaction
	for txid := range uniqueTxIDs {
		// Fetch full transaction details (same as your original code)
		fullArgs := blockchain.GetVerifyTransactionArgs{TransactionID: txid}
		var fullReply blockchain.GetLatestBlockReply
		err := s.client.Call("Blockchain.GetFulTXElect", &fullArgs, &fullReply)
		if err != nil {
			log.Printf("❌ Failed to fetch full transaction for %s: %v", txid, err)
			continue
		}

		var fullTx struct {
			BlockHash     string `json:"blockhash"`
			BlockTime     int64  `json:"blocktime"`
			Confirmations int64  `json:"confirmations"`
			Hash          string `json:"hash"`
			Hex           string `json:"transactionHex"`
			Height        int32  `json:"height"`
			Time          int64  `json:"time"`
			Vout          []struct {
				Value        float64 `json:"value"`
				ScriptPubKey struct {
					Addresses []string `json:"addresses"`
				} `json:"scriptPubKey"`
			} `json:"vout"`
		}
		if err := json.Unmarshal([]byte(fullReply.JSONString), &fullTx); err != nil {
			log.Printf("❌ Failed to decode transaction JSON for %s: %v", txid, err)
			continue
		}
		rawBytes, err := hex.DecodeString(fullTx.Hex)
		if err != nil {
			log.Printf("❌ invalid hex for %s: %v", txid, err)
			continue
		}
		if !isSegWitTransaction(rawBytes) {
			log.Printf("❌ transaction %s is not a SegWit transaction, skipping", txid)
			continue
		}
		// ** CRITICAL CHANGE HERE **
		// Calculate the amount by summing up the value of all outputs that belong to OUR wallet.
		var amount int64
		for _, out := range fullTx.Vout {
			for _, outAddr := range out.ScriptPubKey.Addresses {
				// Check if the output address is one of ours
				if _, ok := walletAddresses[outAddr]; ok {
					amount += int64(out.Value * 1e8) // Convert BTC to sats
				}
			}
		}

		// Only include transactions that are relevant to our wallet (i.e., we received funds)
		if amount > 0 {
			transactions = append(transactions, &lnrpc.Transaction{
				TxHash:           fullTx.Hash,
				Amount:           amount,
				NumConfirmations: int32(fullTx.Confirmations),
				BlockHash:        fullTx.BlockHash,
				BlockHeight:      fullTx.Height,
				TimeStamp:        fullTx.Time,
				RawTxHex:         fullTx.Hex,
			})
		}
	}

	log.Printf("✅ [GetTransactions] Returning %d processed transactions.", len(transactions))
	return &lnrpc.TransactionDetails{Transactions: transactions}, nil
}*/
// Add this struct definition if you don't have it already
type FullTxElectrum struct {
	BlockHash     string `json:"blockhash"`
	BlockTime     int64  `json:"blocktime"`
	Confirmations int64  `json:"confirmations"`
	Hash          string `json:"hash"`
	Hex           string `json:"transactionHex"`
	Height        int32  `json:"height"`
	Time          int64  `json:"time"`
	Vin           []struct {
		Txid string `json:"txid"`
		Vout int    `json:"vout"`
	} `json:"vin"`
	Vout []struct {
		N            int     `json:"n"`
		Value        float64 `json:"value"`
		ScriptPubKey struct {
			Addresses []string `json:"addresses"`
		} `json:"scriptPubKey"`
	} `json:"vout"`
}

// GetTransactions calculates the net change in balance for each transaction.
// This is the function LNDhub ACTUALLY CALLS to determine the wallet balance.
func (s *mockLndServer) GetTransactions(ctx context.Context, req *lnrpc.GetTransactionsRequest) (*lnrpc.TransactionDetails, error) {

	// 1. Discover all wallet addresses (same as before)
	account := req.Account
	if account == "" {
		account = "default"
	}
	log.Println("✅ [GetTransactions] Called (This is the real balance entrypoint for LNDhub) for Account:", account)
	seed, ok := s.seed[account]
	if !ok {
		return nil, fmt.Errorf("account not found: %s", account)
	}
	s.mu.RLock()
	currentIndex := s.nextIndex[account]
	s.mu.RUnlock()
	const gapLimit = 20
	scanUpto := currentIndex + gapLimit
	walletAddresses := make(map[string]bool)
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	purpose, _ := master.Child(hdkeychain.HardenedKeyStart + 84)
	coin, _ := purpose.Child(hdkeychain.HardenedKeyStart + 0)
	acct, _ := coin.Child(hdkeychain.HardenedKeyStart + 0)
	ext, _ := acct.Child(0)
	for i := uint32(0); i < scanUpto; i++ {
		child, _ := ext.Child(i)
		pub, _ := child.ECPubKey()
		addr, _ := bech32Address("bc", pub.SerializeCompressed())
		walletAddresses[addr] = true
	}
	log.Printf("🔍 [GetTransactions] Discovered %v addresses for wallet.", (walletAddresses))

	// 2. Fetch all unique transaction IDs related to our addresses
	uniqueTxIDs := make(map[string]struct{})
	for addr := range walletAddresses {
		args := blockchain.GetAddressHistoryArgs{Address: addr}
		var historyReply blockchain.GetAddressHistoryReply
		if err := s.client.Call("Blockchain.GetTransactionHistory", &args, &historyReply); err != nil {
			log.Printf("⚠️  Could not get history for address %s: %v", addr, err)
			continue
		}
		for _, txid := range historyReply.TransactionHex {
			uniqueTxIDs[txid] = struct{}{}
		}
	}
	log.Printf("🔍 [GetTransactions] Found %d unique transactions across all addresses.", len(uniqueTxIDs))

	// 3. Process each transaction to determine its net effect on the wallet
	var transactions []*lnrpc.Transaction
	for txid := range uniqueTxIDs {
		fullArgs := blockchain.GetVerifyTransactionArgs{TransactionID: txid}
		var fullReply blockchain.GetLatestBlockReply
		err := s.client.Call("Blockchain.GetFulTXElect", &fullArgs, &fullReply)
		if err != nil {
			continue
		}
		var tx FullTxElectrum
		if err := json.Unmarshal([]byte(fullReply.JSONString), &tx); err != nil {
			continue
		}
		rawBytes, err := hex.DecodeString(tx.Hex)
		if err != nil {
			log.Printf("❌ invalid hex for %s: %v", txid, err)
			continue
		}
		if !isSegWitTransaction(rawBytes) {
			log.Printf("❌ transaction %s is not a SegWit transaction, skipping", txid)
			continue
		}
		// Calculate credits: sum of all outputs sent TO US in this tx.
		var totalCredits int64
		for _, out := range tx.Vout {
			for _, addr := range out.ScriptPubKey.Addresses {
				if _, isOurAddress := walletAddresses[addr]; isOurAddress {
					totalCredits += int64(out.Value * 1e8)
				}
			}
		}

		// Calculate debits: sum of all inputs FROM US in this tx.
		var totalDebits int64
		for _, in := range tx.Vin {
			prevTxArgs := blockchain.GetVerifyTransactionArgs{TransactionID: in.Txid}
			var prevTxReply blockchain.GetLatestBlockReply
			err := s.client.Call("Blockchain.GetFulTXElect", &prevTxArgs, &prevTxReply)
			if err != nil {
				continue
			}
			var prevTx FullTxElectrum
			if err := json.Unmarshal([]byte(prevTxReply.JSONString), &prevTx); err != nil {
				continue
			}

			if in.Vout < len(prevTx.Vout) {
				spentOutput := prevTx.Vout[in.Vout]
				for _, addr := range spentOutput.ScriptPubKey.Addresses {
					if _, isOurAddress := walletAddresses[addr]; isOurAddress {
						totalDebits += int64(spentOutput.Value * 1e8)
						break
					}
				}
			}
		}

		// The final amount for this transaction is the net difference.
		netAmount := totalCredits - totalDebits

		if netAmount != 0 {
			log.Printf("ℹ️ [GetTransactions] Processed Tx %s: Credits=%d, Debits=%d, Net=%d", tx.Hash, totalCredits, totalDebits, netAmount)
			transactions = append(transactions, &lnrpc.Transaction{
				TxHash:           tx.Hash,
				Amount:           netAmount, // CRITICAL: This will be positive or negative
				NumConfirmations: int32(tx.Confirmations + 3),
				BlockHash:        tx.BlockHash,
				BlockHeight:      tx.Height,
				TimeStamp:        tx.Time,
				RawTxHex:         tx.Hex,
			})
		}
	}

	/**
		type Transaction struct {
			state         protoimpl.MessageState
			sizeCache     protoimpl.SizeCache
			unknownFields protoimpl.UnknownFields

			// The transaction hash
			TxHash string `protobuf:"bytes,1,opt,name=tx_hash,json=txHash,proto3" json:"tx_hash,omitempty"`
			// The transaction amount, denominated in satoshis
			Amount int64 `protobuf:"varint,2,opt,name=amount,proto3" json:"amount,omitempty"`
			// The number of confirmations
			NumConfirmations int32 `protobuf:"varint,3,opt,name=num_confirmations,json=numConfirmations,proto3" json:"num_confirmations,omitempty"`

			// The hash of the block this transaction was included in
			BlockHash string `protobuf:"bytes,4,opt,name=block_hash,json=blockHash,proto3" json:"block_hash,omitempty"`
			// The height of the block this transaction was included in
			BlockHeight int32 `protobuf:"varint,5,opt,name=block_height,json=blockHeight,proto3" json:"block_height,omitempty"`
			// Timestamp of this transaction
			TimeStamp int64 `protobuf:"varint,6,opt,name=time_stamp,json=timeStamp,proto3" json:"time_stamp,omitempty"`
			// Fees paid for this transaction
			TotalFees int64 `protobuf:"varint,7,opt,name=total_fees,json=totalFees,proto3" json:"total_fees,omitempty"`
			// Deprecated: Do not use.
			DestAddresses []string `protobuf:"bytes,8,rep,name=dest_addresses,json=destAddresses,proto3" json:"dest_addresses,omitempty"`
			// Outputs that received funds for this transaction
			OutputDetails []*OutputDetail `protobuf:"bytes,11,rep,name=output_details,json=outputDetails,proto3" json:"output_details,omitempty"`
			// The raw transaction hex.
			RawTxHex string `protobuf:"bytes,9,opt,name=raw_tx_hex,json=rawTxHex,proto3" json:"raw_tx_hex,omitempty"`
			// A label that was optionally set on transaction broadcast.
			Label string `protobuf:"bytes,10,opt,name=label,proto3" json:"label,omitempty"`
			 // PreviousOutpoints/Inputs of this transaction.
	    PreviousOutpoints []*PreviousOutPoint `protobuf:"bytes,12,rep,name=previous_outpoints,json=previousOutpoints,proto3" json:"previous_outpoints,omitempty"`
	}
	*/
	log.Printf("✅ [GetTransactions] Returning %d processed transactions with net amounts.", len(transactions))
	return &lnrpc.TransactionDetails{Transactions: transactions}, nil
}

// isSegWitTransaction returns true if the raw tx bytes have the
// marker/flag indicating a v0 witness (native SegWit).
func isSegWitTransaction(raw []byte) bool {
	if len(raw) < 6 {
		return false
	}
	// after 4‑byte version comes [0x00][non‑zero] for SegWit v0
	return raw[4] == 0x00 && raw[5] != 0x00
}

// Add this method to your mockLndServer struct in main.go
// ListUnspent returns the set of UTXOs in the wallet, exactly as LndHub expects
func (s *mockLndServer) ListUnspent(ctx context.Context, req *lnrpc.ListUnspentRequest) (*lnrpc.ListUnspentResponse, error) {
	log.Println("✅ [ListUnspent] Called")

	// 1) Discover your wallet addresses (like in GetTransactions)
	account := req.Account
	if account == "" {
		account = "default"
	}
	seed, ok := s.seed[account]
	if !ok {
		return nil, fmt.Errorf("account not found: %s", account)
	}

	s.mu.RLock()
	currentIdx := s.nextIndex[account]
	s.mu.RUnlock()
	const gapLimit = 20
	scanUpto := currentIdx + gapLimit

	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	purpose, _ := master.Child(hdkeychain.HardenedKeyStart + 84)
	coin, _ := purpose.Child(hdkeychain.HardenedKeyStart + 0)
	acct, _ := coin.Child(hdkeychain.HardenedKeyStart + 0)
	ext, _ := acct.Child(0)

	var utxos []*lnrpc.Utxo
	for i := uint32(0); i < scanUpto; i++ {
		child, _ := ext.Child(i)
		pub, _ := child.ECPubKey()
		addr, _ := bech32Address("bc", pub.SerializeCompressed())

		// Call miniBTCD RPC to fetch UTXOs for this address
		args := blockchain.GetBalanceArgs{Address: addr, Amount: 0}
		var reply blockchain.GetLatestBlockReply
		if err := s.client.Call("Blockchain.GetAddressUTXOs", &args, &reply); err != nil {
			log.Printf("⚠️  Could not get UTXOs for %s: %v", addr, err)
			continue
		}

		// reply.JSONBlock is a JSON map of TXID -> TXOutput
		var raw map[string]*trx.TXOutput
		if err := json.Unmarshal([]byte(reply.JSONBlock), &raw); err != nil {
			log.Printf("⚠️  Failed to parse UTXOs JSON for %s: %v", addr, err)
			continue
		}

		for txid, output := range raw {
			utxos = append(utxos, &lnrpc.Utxo{
				Address:       addr,
				AmountSat:     int64(output.Value),
				Outpoint:      &lnrpc.OutPoint{TxidBytes: []byte(txid), TxidStr: txid, OutputIndex: 0},
				PkScript:      output.PubKeyHash,
				Confirmations: 0,
			})
		}
	}

	log.Printf("ℹ️ [ListUnspent] Returning %d UTXOs\n", len(utxos))
	return &lnrpc.ListUnspentResponse{Utxos: utxos}, nil
}

// WalletBalance provides a detailed view of the wallet's balance, combining both
// on-chain UTXOs and the value from settled off-chain invoices.
func (s *mockLndServer) WalletBalance(ctx context.Context, req *lnrpc.WalletBalanceRequest) (*lnrpc.WalletBalanceResponse, error) {
	log.Println("✅ [WalletBalance] Called (Comprehensive Balance Calculation)")

	// --- 1. Calculate On-Chain Balance ---
	// We re-use the logic from GetTransactions to find the on-chain balance.
	txDetails, err := s.GetTransactions(ctx, &lnrpc.GetTransactionsRequest{Account: req.Account})
	if err != nil {
		log.Printf("❌ [WalletBalance] Error getting transactions: %v", err)
		return nil, err
	}
	var onChainBalance int64
	for _, tx := range txDetails.Transactions {
		// Only count confirmed transactions towards the balance
		if tx.NumConfirmations > 0 {
			onChainBalance += tx.Amount
		}
	}
	log.Printf("💰 [WalletBalance] Calculated On-Chain balance: %d sats", onChainBalance)

	// --- 2. Calculate Off-Chain Balance (from settled invoices) ---
	s.mu.RLock()
	var offChainBalance int64
	for _, inv := range s.invoices {
		if inv.State == lnrpc.Invoice_SETTLED {
			offChainBalance += inv.AmtPaidSat
		}
	}
	s.mu.RUnlock()
	log.Printf("⚡️ [WalletBalance] Calculated Off-Chain (invoice) balance: %d sats", offChainBalance)

	// --- 3. Combine Balances for the final response ---
	// LNDhub's balance is typically seen as the off-chain/lightning balance.
	// However, the total balance should reflect everything.
	totalBalance := onChainBalance + offChainBalance

	log.Printf("📊 [WalletBalance] Final balance -> Total: %d, Confirmed On-Chain: %d", totalBalance, onChainBalance)

	// A real LND would differentiate channel balances here, but for LNDhub,
	// the sum of settled invoices is a good proxy for the available lightning balance.
	return &lnrpc.WalletBalanceResponse{
		TotalBalance:       totalBalance,
		ConfirmedBalance:   onChainBalance,
		UnconfirmedBalance: 0, // Simplified for now
		LockedBalance:      0,
		AccountBalance: map[string]*lnrpc.WalletAccountBalance{
			"default": {
				ConfirmedBalance:   onChainBalance,
				UnconfirmedBalance: 0,
			},
		},
	}, nil
}
func (s *mockLndServer) SubscribeInvoices(req *lnrpc.InvoiceSubscription, stream lnrpc.Lightning_SubscribeInvoicesServer) error {
	log.Println("✅ [SubscribeInvoices] New client subscribed!")
	for {
		select {
		case <-stream.Context().Done():
			log.Println("👋 [SubscribeInvoices] Client disconnected.")
			return nil
		case invoiceUpdate := <-s.invoiceChan:
			log.Printf("📢 [SubscribeInvoices] Sending update for invoice hash: %s", hex.EncodeToString(invoiceUpdate.RHash))
			if err := stream.Send(invoiceUpdate); err != nil {
				log.Printf("❌ [SubscribeInvoices] Error sending update to client: %v", err)
				return err
			}
		}
	}
}

// Add these helper functions to your mockLndServer

// hash160 returns the RIPEMD-160 hash of the SHA-256 hash of the input data
func hash160(data []byte) []byte {
	sha := sha256.Sum256(data)
	ripemd := ripemd160.New()
	ripemd.Write(sha[:])
	return ripemd.Sum(nil)
}

// convertBits converts between groups of bits for bech32 encoding
func convertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	acc := uint32(0)
	bits := uint(0)
	ret := []byte{}
	maxv := uint32(1<<toBits) - 1
	maxAcc := uint32(1<<(fromBits+toBits-1)) - 1

	for _, value := range data {
		if value>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range: value %d exceeds %d bits", value, fromBits)
		}
		acc = ((acc << fromBits) | uint32(value)) & maxAcc

		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>uint32(bits))&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("invalid padding")
	}
	return ret, nil
}

// bech32Encode encodes data to a Bech32 string
func bech32Encode(hrp string, data []byte) (string, error) {
	const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	// Calculate the checksum
	checksum := bech32Checksum(hrp, data)

	// Combine the data and checksum
	combined := append(data, checksum...)

	// Encode the combined data and checksum to a Bech32 string
	var result string
	for _, value := range combined {
		if value >= 32 {
			return "", fmt.Errorf("invalid data value: %d", value)
		}
		result += string(alphabet[value])
	}

	return hrp + "1" + result, nil
}

// bech32Checksum creates a Bech32 checksum
func bech32Checksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, []byte{0, 0, 0, 0, 0, 0}...)
	mod := polyMod(values) ^ 1
	checksum := make([]byte, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return checksum
}

// polyMod calculates the Bech32 checksum
func polyMod(values []byte) uint32 {
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ uint32(v)
		if (b & 1) != 0 {
			chk ^= 0x3b6a57b2
		}
		if (b & 2) != 0 {
			chk ^= 0x26508e6d
		}
		if (b & 4) != 0 {
			chk ^= 0x1ea119fa
		}
		if (b & 8) != 0 {
			chk ^= 0x3d4233dd
		}
		if (b & 16) != 0 {
			chk ^= 0x2a1462b3
		}
	}
	return chk
}

// hrpExpand expands the HRP for checksum calculation
func hrpExpand(hrp string) []byte {
	hrpLen := len(hrp)
	exp := make([]byte, hrpLen*2+1)
	for i := 0; i < hrpLen; i++ {
		exp[i] = hrp[i] >> 5
		exp[i+hrpLen+1] = hrp[i] & 31
	}
	exp[hrpLen] = 0
	return exp
}

/*
	func (s *mockLndServer) generateNewAddress(addrType lnrpc.AddressType, account string) (string, error) {
		s.mu.Lock()

		if account == "" {
			account = "default"
		}
		idx := s.nextIndex[account]
		s.nextIndex[account] = idx + 1
		s.mu.Unlock()

		// 1) Master key from seed on mainnet
		master, err := hdkeychain.NewMaster(s.seed[account], &chaincfg.MainNetParams)
		if err != nil {
			return "", fmt.Errorf("hd new master: %w", err)
		}

		// 2) Derivation path m/84'/0'/0'/0/idx for native P2WPKH on mainnet:
		purpose, err := master.Child(hdkeychain.HardenedKeyStart + 84)
		if err != nil {
			return "", err
		}
		coin, err := purpose.Child(hdkeychain.HardenedKeyStart + 0) // 0' for mainnet
		if err != nil {
			return "", err
		}
		acct, err := coin.Child(hdkeychain.HardenedKeyStart + 0)
		if err != nil {
			return "", err
		}
		ext, err := acct.Child(0) // external chain
		if err != nil {
			return "", err
		}
		child, err := ext.Child(idx)
		if err != nil {
			return "", err
		}

		pubKey, err := child.ECPubKey()
		if err != nil {
			return "", err
		}
		pubBytes := pubKey.SerializeCompressed()

		// 3) Encode according to requested type:
		switch addrType {
		case lnrpc.AddressType_NESTED_PUBKEY_HASH:
			return s.generateP2SHAddress(pubBytes)
		case lnrpc.AddressType_WITNESS_PUBKEY_HASH:
			fallthrough
		default:
			// native P2WPKH on mainnet uses HRP "bc"
			return bech32Address("bc", pubBytes)
		}
	}
*/
func (s *mockLndServer) saveState() error {
	s.mu.RLock() // Use a read lock, as we are only reading the map to serialize it.
	defer s.mu.RUnlock()

	stateJSON, err := json.MarshalIndent(s.nextIndex, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state to JSON: %w", err)
	}

	err = ioutil.WriteFile(stateFileName, stateJSON, 0644)
	if err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// NEW HELPER FUNCTION: This function reads the existing address log, appends a new record, and writes it back.
// It is designed to be called after a new address has been successfully generated.
// MODIFIED: This function now accepts a time.Time object and saves it as a formatted string.
func (s *mockLndServer) saveGeneratedAddress(index uint32, address string, createdAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var records []AddressRecord
	fileData, err := ioutil.ReadFile(addressesFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read address file '%s': %w", addressesFileName, err)
		}
	} else if len(fileData) > 0 {
		if err := json.Unmarshal(fileData, &records); err != nil {
			return fmt.Errorf("failed to unmarshal existing addresses from '%s': %w", addressesFileName, err)
		}
	}

	// Create the new record, formatting the timestamp.
	newRecord := AddressRecord{
		NextIndex: index,
		Address:   address,
		CreatedAt: createdAt.Format(time.RFC3339), // Format time to a standard string
	}
	records = append(records, newRecord)

	updatedData, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated addresses to JSON: %w", err)
	}

	if err := ioutil.WriteFile(addressesFileName, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write updated addresses to '%s': %w", addressesFileName, err)
	}

	log.Printf("💾 Saved new address to %s: {index: %d, address: %s}", addressesFileName, index, address)
	return nil
}
func (s *mockLndServer) generateNewAddress(addrType lnrpc.AddressType, account string) (string, error) {
	// We know from LNDhub that the 'account' parameter will always be empty,
	// so we will operate exclusively on the "default" wallet.

	// Lock the mutex to safely read and update the address index.
	s.mu.Lock()

	// Get the current index for our single, default wallet.
	idx := s.nextIndex["default"]

	// Immediately increment the index for the next time this function is called.
	// This guarantees the next call will produce a different address.
	s.nextIndex["default"] = idx + 1

	// Get the one and only seed for our mock wallet.
	defaultSeed := s.seed["default"]

	// We are done with shared memory, so we can unlock the mutex.
	s.mu.Unlock()
	if err := s.saveState(); err != nil {
		// Log the error but don't fail the address generation itself.
		// The address was generated correctly in memory.
		log.Printf("❌ CRITICAL: Failed to persist new index state to disk: %v", err)
	}
	log.Printf("🌱 [generateNewAddress] Generating unique address for default wallet at index %d", idx)

	// 1) Create master key from the single default seed.
	master, err := hdkeychain.NewMaster(defaultSeed, &chaincfg.MainNetParams)
	if err != nil {
		return "", fmt.Errorf("error creating master key for default wallet: %w", err)
	}

	// 2) Derivation path m/84'/0'/0'/0/idx using our unique index.
	purpose, err := master.Child(hdkeychain.HardenedKeyStart + 84)
	if err != nil {
		return "", err
	}
	coin, err := purpose.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", err
	}
	acct, err := coin.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return "", err
	}
	ext, err := acct.Child(0)
	if err != nil {
		return "", err
	}

	// Use the unique index `idx` we safely retrieved.
	child, err := ext.Child(idx)
	if err != nil {
		return "", fmt.Errorf("error deriving child key at index %d: %w", idx, err)
	}

	pubKey, err := child.ECPubKey()
	if err != nil {
		return "", fmt.Errorf("error getting pubkey: %w", err)
	}
	pubBytes := pubKey.SerializeCompressed()

	// 3) Encode according to the requested type.
	var address string
	// 3) Encode according to the requested type.
	switch addrType {
	case lnrpc.AddressType_NESTED_PUBKEY_HASH:
		address, err = s.generateP2SHAddress(pubBytes)
	case lnrpc.AddressType_WITNESS_PUBKEY_HASH:
		fallthrough
	default:
		// native P2WPKH on mainnet uses HRP "bc"
		address, err = bech32Address("bc", pubBytes)
	}

	if err != nil {
		// If address generation itself failed, return the error.
		return "", err
	}
	createdAt := time.Now()
	if errSave := s.saveGeneratedAddress(idx, address, createdAt); errSave != nil {
		log.Printf("❌ CRITICAL: Failed to save generated address to disk: %v", errSave)
	}
	return address, nil
}

// Stand‑alone helper for generating a Bech32 (P2WPKH) address.
func bech32Address(hrp string, pubKey []byte) (string, error) {
	// 1) hash160(pubKey)
	sha := sha256.Sum256(pubKey)
	rip := ripemd160.New()
	rip.Write(sha[:])
	pubKeyHash := rip.Sum(nil)

	// 2) convert to 5‑bit groups
	data5, err := convertBits(pubKeyHash, 8, 5, true)
	if err != nil {
		return "", err
	}

	// 3) prepend witness version 0
	witnessProgram := append([]byte{0}, data5...)

	// 4) Bech32‑encode
	return bech32Encode(hrp, witnessProgram)
}

// generateBech32Address creates a Bech32 address (bc1...)
func (s *mockLndServer) generateBech32Address(publicKey []byte) (string, error) {
	// Create hash160 of the public key
	pubKeyHash := hash160(publicKey)

	// Convert to 5-bit array for bech32
	data5, err := convertBits(pubKeyHash, 8, 5, true)
	if err != nil {
		return "", err
	}

	// Prepend witness version (0 for P2WPKH)
	versionData := append([]byte{0}, data5...)

	// Use "bcrt" for regtest, "bc" for mainnet
	hrp := "bc"

	// Create the Bech32 address
	address, err := bech32Encode(hrp, versionData)
	if err != nil {
		return "", err
	}

	log.Printf("Generated Bech32 address: %s from pubkey: %x", address, publicKey)
	return address, nil
}

// generateP2PKHAddress creates a legacy P2PKH address (1...)
func (s *mockLndServer) generateP2PKHAddress(publicKey []byte) (string, error) {
	// Create hash160 of the public key
	pubKeyHash := hash160(publicKey)

	// Add version byte (0x00 for mainnet P2PKH, 0x6f for testnet)
	versionedPayload := append([]byte{0x6f}, pubKeyHash...) // Using testnet prefix

	// Calculate checksum
	checksum := s.calculateChecksum(versionedPayload)

	// Create full address payload
	fullPayload := append(versionedPayload, checksum...)

	// Encode to Base58
	address := s.base58Encode(fullPayload)

	log.Printf("Generated P2PKH address: %s from pubkey: %x", address, publicKey)
	return address, nil
}

// generateP2SHAddress creates a P2SH address (3...)
func (s *mockLndServer) generateP2SHAddress(publicKey []byte) (string, error) {
	// For simplicity, create a simple P2SH-P2WPKH script
	// This is a simplified version - real implementation would be more complex
	pubKeyHash := hash160(publicKey)

	// Create a simple redeem script (this is simplified)
	redeemScript := append([]byte{0x00, 0x14}, pubKeyHash...) // OP_0 PUSH(20) <pubKeyHash>
	scriptHash := hash160(redeemScript)

	// Add version byte (0x05 for mainnet P2SH, 0xc4 for testnet)
	versionedPayload := append([]byte{0xc4}, scriptHash...) // Using testnet prefix

	// Calculate checksum
	checksum := s.calculateChecksum(versionedPayload)

	// Create full address payload
	fullPayload := append(versionedPayload, checksum...)

	// Encode to Base58
	address := s.base58Encode(fullPayload)

	log.Printf("Generated P2SH address: %s from pubkey: %x", address, publicKey)
	return address, nil
}

// calculateChecksum calculates double SHA256 checksum
func (s *mockLndServer) calculateChecksum(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// base58Encode encodes bytes to Base58
func (s *mockLndServer) base58Encode(input []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// Convert to big integer
	value := new(big.Int).SetBytes(input)

	// Convert to base58
	result := make([]byte, 0, len(input)*136/100)
	for value.Sign() > 0 {
		mod := new(big.Int)
		value.DivMod(value, big.NewInt(58), mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Add leading zeros
	for i := 0; i < zeros; i++ {
		result = append(result, alphabet[0])
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// Updated NewAddress method
func (s *mockLndServer) NewAddress(ctx context.Context, req *lnrpc.NewAddressRequest) (*lnrpc.NewAddressResponse, error) {
	log.Printf("✅ [NewAddress] Called with type: %v for User: %s", req.Type, req.Account)

	// Generate a real address based on the node's public key
	address, err := s.generateNewAddress(req.Type, req.Account)
	if err != nil {
		log.Printf("❌ [NewAddress] Failed to generate address: %v", err)
		return nil, err
	}

	return &lnrpc.NewAddressResponse{
		Address: address,
	}, nil
}

// in main.go

// DecodePayReq implements the RPC call to parse a BOLT11 invoice.
// LNDhub uses this as a pre-flight check before attempting payment.
func (s *mockLndServer) DecodePayReq(ctx context.Context, req *lnrpc.PayReqString) (*lnrpc.PayReq, error) {
	log.Printf("✅ [DecodePayReq] Called for invoice: %.30s...", req.PayReq)

	parsed, err := s.parseInvoiceManually(req.PayReq)
	if err != nil {
		log.Printf("❌ [DecodePayReq] Failed to parse invoice: %v", err)
		return nil, err
	}

	log.Printf("📄 [DecodePayReq] Successfully parsed invoice. Payment Hash: %s", parsed.PaymentHash)
	return parsed, nil
}

func (s *mockLndServer) parseInvoiceManually(payReq string) (*lnrpc.PayReq, error) {
	hrp, data5, err := bech32.DecodeNoLimit(payReq)
	if err != nil {
		return nil, fmt.Errorf("bech32 decode failed: %w", err)
	}

	if len(data5) < 7 {
		return nil, errors.New("invoice too short")
	}

	// Parse timestamp (7 * 5-bit = 35 bits) - Fixed bit shifting
	timestamp := int64(0)
	for i := 0; i < 7; i++ {
		timestamp = (timestamp << 5) | int64(data5[i])
	}

	taggedData := data5[7:]

	var (
		paymentHash string
		description string
		expiry      int64 = 3600 // default
	)

	for len(taggedData) >= 3 {
		tag := taggedData[0]
		// Fixed length calculation - it's 10 bits (2 * 5-bit values)
		dataLength := int(taggedData[1])<<5 | int(taggedData[2])
		taggedData = taggedData[3:]

		if len(taggedData) < dataLength {
			log.Printf("⚠️ Field tag %d: expected length %d, but only %d remain", tag, dataLength, len(taggedData))
			break
		}

		field5 := taggedData[:dataLength]
		taggedData = taggedData[dataLength:]

		switch tag {
		case 1: // Payment hash (p = 1 in 5-bit encoding, not 'p')
			field8, err := bech32.ConvertBits(field5, 5, 8, false)
			if err != nil {
				log.Printf("⚠️ Failed to convert payment hash data: %v", err)
				continue
			}
			paymentHash = hex.EncodeToString(field8)

		case 13: // Description (d = 13 in 5-bit encoding, not 'd')
			field8, err := bech32.ConvertBits(field5, 5, 8, false)
			if err != nil {
				log.Printf("⚠️ Failed to convert description data: %v", err)
				continue
			}
			description = string(field8)

		case 6: // Expiry time (x = 6 in 5-bit encoding)
			expiryValue := int64(0)
			for _, val := range field5 {
				expiryValue = (expiryValue << 5) | int64(val)
			}
			expiry = expiryValue

		default:
			// Skip unsupported tags silently
			log.Printf("📝 Skipping unsupported tag: %d (length: %d)", tag, dataLength)
		}
	}

	// Parse amount from HRP (e.g. lnbc7u -> 7u)
	numSats := int64(0)
	re := regexp.MustCompile(`[0-9]+[munp]?`)
	match := re.FindString(hrp)
	if match != "" {
		numSats = parseHRPAmount(match)
	}

	if paymentHash == "" {
		return nil, errors.New("missing payment hash in invoice")
	}

	return &lnrpc.PayReq{
		Destination: hex.EncodeToString(s.nodePublicKey.SerializeCompressed()),
		PaymentHash: paymentHash,
		NumSatoshis: numSats,
		Timestamp:   timestamp,
		Expiry:      expiry,
		Description: description,
	}, nil
}

func parseHRPAmount(hrp string) int64 {
	// Handle case where there's no amount specified
	if len(hrp) == 0 {
		return 0
	}

	unit := hrp[len(hrp)-1]
	numStr := hrp

	var multiplier float64 = 1e8 // default: BTC to satoshi

	// Check if last character is a unit
	if unit == 'm' || unit == 'u' || unit == 'n' || unit == 'p' {
		numStr = hrp[:len(hrp)-1]
		switch unit {
		case 'm': // milli-bitcoin (0.001 BTC)
			multiplier = 1e5 // 100,000 sats
		case 'u': // micro-bitcoin (0.000001 BTC)
			multiplier = 1e2 // 100 sats
		case 'n': // nano-bitcoin (0.000000001 BTC)
			multiplier = 0.1 // 0.1 sats
		case 'p': // pico-bitcoin (0.000000000001 BTC)
			multiplier = 0.0001 // 0.0001 sats
		}
	}

	if numStr == "" {
		return 0
	}

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}

	return int64(num * multiplier)
}

// SendPaymentSync intelligently simulates paying a Lightning invoice without external dependencies.
// It manually decodes the invoice to find the payment hash, checks if it's an internal
// invoice, and uses the real preimage if possible.
func (s *mockLndServer) SendPaymentSync(ctx context.Context, req *lnrpc.SendRequest) (*lnrpc.SendResponse, error) {
	log.Printf("✅ [SendPaymentSync] Called with payment request: %.30s...", req.PaymentRequest)

	// Step 1: Manually parse the invoice to extract the payment hash.
	paymentHashBytes, err := getPaymentHashFromInvoice(req.PaymentRequest)
	if err != nil {
		log.Printf("❌ [SendPaymentSync] Failed to parse payment request: %v", err)
		return &lnrpc.SendResponse{PaymentError: "invalid payment request"}, nil
	}
	paymentHash := hex.EncodeToString(paymentHashBytes)

	// Step 2: Check if this is an internal invoice that we created.
	s.mu.RLock()
	invoice, isInternal := s.invoices[paymentHash]
	s.mu.RUnlock()

	var preimage []byte

	if isInternal {
		// --- INTERNAL PAYMENT PATH ---
		log.Printf("ℹ️ [SendPaymentSync] This is an INTERNAL payment. Using real preimage.")
		preimage = invoice.RPreimage // Use the real, stored preimage.
		go s.settleInternalInvoice(paymentHash)
	} else {
		// --- EXTERNAL PAYMENT PATH ---
		log.Printf("ℹ️ [SendPaymentSync] This is an EXTERNAL payment. Generating random preimage.")
		randomPreimage := make([]byte, 32)
		if _, err := rand.Read(randomPreimage); err != nil {
			log.Printf("❌ [SendPaymentSync] Failed to generate random preimage: %v", err)
			return &lnrpc.SendResponse{PaymentError: "Failed to generate preimage"}, nil
		}
		preimage = randomPreimage
	}

	time.Sleep(1 * time.Second) // Simulate network delay

	var amtMsat int64
	if req.AmtMsat > 0 {
		amtMsat = req.AmtMsat
	} else if req.Amt > 0 {
		amtMsat = req.Amt * 1000
	}

	mockRoute := &lnrpc.Route{
		TotalTimeLock: 60,
		TotalAmtMsat:  amtMsat,
		TotalFeesMsat: 5000,
		Hops: []*lnrpc.Hop{
			{ChanId: 123456789, AmtToForwardMsat: amtMsat, FeeMsat: 5000},
		},
	}

	log.Printf("💸 [SendPaymentSync] Payment successful! Preimage: %s", hex.EncodeToString(preimage))

	return &lnrpc.SendResponse{
		PaymentError:    "",
		PaymentPreimage: preimage,
		PaymentHash:     paymentHashBytes,
		PaymentRoute:    mockRoute,
	}, nil
}

// getPaymentHashFromInvoice decodes a BOLT11 string and extracts the payment hash
// without needing the full zpay32 library.
func getPaymentHashFromInvoice(payReq string) ([]byte, error) {
	// Decode the bech32 string to get the raw 5-bit data part.
	_, data, err := bech32.Decode(payReq)
	if err != nil {
		return nil, fmt.Errorf("bech32 decode failed: %w", err)
	}

	// The first part of the data is the timestamp (7 groups of 5 bits).
	// We need to skip this to get to the tagged data section.
	if len(data) < 7 {
		return nil, errors.New("invoice data too short for timestamp")
	}
	taggedData := data[7:]

	// Now, iterate through the tagged fields.
	for len(taggedData) > 0 {
		tag := taggedData[0]

		if len(taggedData) < 3 {
			return nil, errors.New("invalid tagged field format")
		}

		// The next two 5-bit groups represent the length of the data.
		dataLen := int(taggedData[1])<<5 | int(taggedData[2])

		// Check if we have enough data for this field.
		if len(taggedData) < 3+dataLen {
			return nil, errors.New("data length exceeds remaining buffer")
		}

		// The tag 'p' (value 1) is for the payment hash.
		if tag == 1 {
			hashData5Bit := taggedData[3 : 3+dataLen]

			// Convert the 5-bit hash data back to 8-bit bytes.
			hashData8Bit, err := bech32.ConvertBits(hashData5Bit, 5, 8, false)
			if err != nil {
				return nil, fmt.Errorf("failed to convert payment hash bits: %w", err)
			}

			// A payment hash must be 32 bytes (256 bits).
			if len(hashData8Bit) != 32 {
				return nil, fmt.Errorf("invalid payment hash length: got %d, want 32", len(hashData8Bit))
			}

			return hashData8Bit, nil
		}

		// Move to the next tagged field.
		taggedData = taggedData[3+dataLen:]
	}

	return nil, errors.New("payment hash not found in invoice")
}

// You will also need this helper function if you don't already have it.
func (s *mockLndServer) settleInternalInvoice(rhashHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	invoice, ok := s.invoices[rhashHex]
	if !ok || invoice.State == lnrpc.Invoice_SETTLED {
		return // Already settled or doesn't exist
	}

	invoice.State = lnrpc.Invoice_SETTLED
	invoice.SettleDate = time.Now().Unix()
	invoice.AmtPaidSat = invoice.Value
	invoice.AmtPaidMsat = invoice.Value * 1000

	log.Printf("✅ [settleInternalInvoice] Invoice %s has been settled internally!", rhashHex)

	// Send notification for subscribers
	s.invoiceChan <- invoice
}
func (s *mockLndServer) AddInvoice(ctx context.Context, in *lnrpc.Invoice) (*lnrpc.AddInvoiceResponse, error) {
	log.Printf("✅ [AddInvoice] Called for %d sats with memo: '%s'", in.Value, in.Memo)
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate payment hash
	rhashBytes := make([]byte, 32)
	rand.Read(rhashBytes)
	rhashHex := hex.EncodeToString(rhashBytes)
	creationDate := time.Now().Unix()

	// Build the BOLT11 invoice
	paymentRequest, err := s.createBOLT11Invoice(in.Value, rhashBytes, creationDate, in.Memo)
	if err != nil {
		return nil, fmt.Errorf("failed to create BOLT11 invoice: %w", err)
	}

	log.Printf("📄 [AddInvoice] Generated valid payment request: %s", paymentRequest)

	// Store the invoice
	in.RHash = rhashBytes
	in.CreationDate = creationDate
	in.State = lnrpc.Invoice_OPEN
	in.PaymentRequest = paymentRequest
	in.AddIndex = uint64(len(s.invoices) + 1)
	s.invoices[rhashHex] = in

	log.Printf("📝 [AddInvoice] Created invoice with hash: %s", rhashHex)
	//go s.simulatePayment(rhashHex, 15*time.Second)

	return &lnrpc.AddInvoiceResponse{
		RHash:          in.RHash,
		PaymentRequest: in.PaymentRequest,
		AddIndex:       in.AddIndex,
	}, nil
}

func (s *mockLndServer) createBOLT11Invoice(amountMsat int64, paymentHash []byte, timestamp int64, description string) (string, error) {
	// Build the human-readable part (HRP)
	hrp := "lnbc"
	if amountMsat > 0 {
		amountSats := amountMsat / 1000
		hrp += fmt.Sprintf("%du", amountSats)
	}

	var data []byte

	// 1. Add timestamp (7 groups of 5 bits = 35 bits total)
	ts := uint64(timestamp)
	for i := 6; i >= 0; i-- {
		data = append(data, byte((ts>>(uint(i)*5))&0x1f))
	}

	// 2. Add payment hash tag ('p')
	data = append(data, 1) // tag 'p'
	hashData, err := bech32.ConvertBits(paymentHash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert payment hash: %w", err)
	}
	// Encode length in two 5-bit words
	length := len(hashData)
	data = append(data, byte(length>>5), byte(length&31))
	data = append(data, hashData...)

	// 3. Add description tag ('d') if provided
	if description != "" {
		data = append(data, 13) // tag 'd'
		descData, err := bech32.ConvertBits([]byte(description), 8, 5, true)
		if err != nil {
			return "", fmt.Errorf("failed to convert description: %w", err)
		}
		length := len(descData)
		data = append(data, byte(length>>5), byte(length&31))
		data = append(data, descData...)
	}

	// 4. Add node public key tag ('n') - required by BlueWallet
	data = append(data, 19) // tag 'n'
	pubKeyData, err := bech32.ConvertBits(s.nodePublicKey.SerializeCompressed(), 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key: %w", err)
	}
	length = len(pubKeyData)
	data = append(data, byte(length>>5), byte(length&31))
	data = append(data, pubKeyData...)

	// Prepare message for signing (HRP + converted data bytes)
	msgToSign := []byte(hrp)
	dataBytes, err := bech32.ConvertBits(data, 5, 8, true)
	if err != nil {
		return "", fmt.Errorf("failed to prepare signing data: %w", err)
	}
	msgToSign = append(msgToSign, dataBytes...)

	// 5. Sign message
	signature, recoveryID, err := s.signMessage(msgToSign)
	if err != nil {
		return "", fmt.Errorf("failed to sign invoice: %w", err)
	}

	// 6. Add signature to data
	fullSig := append(signature, recoveryID)
	sigData, err := bech32.ConvertBits(fullSig, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert signature: %w", err)
	}
	data = append(data, sigData...)

	// 7. Final Bech32 encoding
	invoice, err := bech32.Encode(hrp, data)
	if err != nil {
		return "", fmt.Errorf("failed to encode invoice: %w", err)
	}

	return invoice, nil
}
func (s *mockLndServer) signMessage(message []byte) ([]byte, byte, error) {
	// Hash the message with SHA256
	h := sha256.Sum256(message)

	// Sign using ECDSA
	r, x, err := ecdsa.Sign(rand.Reader, s.nodePrivateKey.ToECDSA(), h[:])
	if err != nil {
		return nil, 0, fmt.Errorf("ecdsa signing failed: %w", err)
	}

	// Format signature as 64 bytes (32 bytes r + 32 bytes s)
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := x.Bytes()

	// Right-pad with zeros if needed
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)

	// Calculate the correct recovery ID by testing which one recovers to our public key
	expectedPubKey := s.nodePublicKey.SerializeCompressed()

	for recoveryID := byte(0); recoveryID < 4; recoveryID++ {
		// Test recovery with this ID
		recoveredPubKey, err := recoverPublicKey(h[:], signature, recoveryID)
		if err != nil {
			continue
		}

		// Check if recovered key matches our expected key
		if bytes.Equal(recoveredPubKey, expectedPubKey) {
			return signature, recoveryID, nil
		}
	}

	return nil, 0, fmt.Errorf("could not find valid recovery ID")
}

// Helper function to recover public key from signature
func recoverPublicKey(hash []byte, signature []byte, recoveryID byte) ([]byte, error) {
	// Create the signature in the format expected by ecdsa.RecoverCompact
	// RecoverCompact expects: [recovery_id + 27][r][s] (65 bytes total)
	compactSig := make([]byte, 65)
	compactSig[0] = recoveryID + 27
	copy(compactSig[1:], signature)

	// Use ecdsa.RecoverCompact to recover the public key
	pubKey, _, err := ecdsa_.RecoverCompact(compactSig, hash)
	if err != nil {
		return nil, err
	}

	return pubKey.SerializeCompressed(), nil
}

// --- Router Service Implementation (on mockRouterServer) ---

func (r *mockRouterServer) SendPaymentV2(req *routerrpc.SendPaymentRequest, stream routerrpc.Router_SendPaymentV2Server) error {
	log.Printf("✅ [Router.SendPaymentV2] Called for payment_hash: %s, amount: %d sats", hex.EncodeToString(req.PaymentHash), req.Amt)
	// Note: We don't need to lock the mutex here since we are not accessing shared state.
	// If we were to deduct a balance, we would use r.mainServer.mu.Lock()

	time.Sleep(2 * time.Second)

	finalState := &lnrpc.Payment{
		PaymentHash:  hex.EncodeToString(req.PaymentHash),
		ValueSat:     req.Amt,
		FeeSat:       5,
		Status:       lnrpc.Payment_SUCCEEDED,
		CreationDate: time.Now().Unix(),
	}

	log.Printf("💸 [Router.SendPaymentV2] Payment successful!")
	return stream.Send(finalState)
}

// --- Helper Functions (on mockLndServer) ---

func (s *mockLndServer) simulatePayment(rhashHex string, delay time.Duration) {
	log.Printf("⏳ [Simulator] Payment for invoice %s will be simulated in %v...", rhashHex, delay)
	time.Sleep(delay)
	s.mu.Lock()
	defer s.mu.Unlock()

	invoice, ok := s.invoices[rhashHex]
	if !ok {
		return
	}

	invoice.State = lnrpc.Invoice_SETTLED
	invoice.SettleDate = time.Now().Unix()
	invoice.AmtPaidSat = invoice.Value
	log.Printf("✅ [Simulator] Invoice %s has been settled!", rhashHex)
	s.invoiceChan <- invoice
}
func main() {
	rpcServerAddr := flag.String("rpcserver", "16.171.227.75:18885", "host:port of the miniBTCD RPC server")

	// NEW: Parse the command-line flags.
	flag.Parse()
	// --- TLS Setup ---
	_, err := credentials.NewServerTLSFromFile("tls.cert", "tls.key")
	if err != nil {
		log.Println("⚠️ TLS certs not found. Generating new ones...")
		err := generateCerts()
		if err != nil {
			log.Fatalf("failed to generate certs: %v", err)
		}
	}
	creds, err := credentials.NewServerTLSFromFile("tls.cert", "tls.key")
	if err != nil {
		log.Fatalf("failed to load TLS keys after generation: %v", err)
	}
	opts := []grpc.ServerOption{grpc.Creds(creds)}
	grpcServer := grpc.NewServer(opts...)

	// --- Server Registration ---
	mainServer := NewMockLndServer(*rpcServerAddr)
	routerServer := &mockRouterServer{mainServer: mainServer}
	lnrpc.RegisterLightningServer(grpcServer, mainServer)
	invoicesrpc.RegisterInvoicesServer(grpcServer, mainServer)
	routerrpc.RegisterRouterServer(grpcServer, routerServer)

	reflection.Register(grpcServer)

	// --- New: Bake the admin macaroon on startup ---
	// Create a request with all the standard permissions LNDhub needs.
	bakeReq := &lnrpc.BakeMacaroonRequest{
		Permissions: []*lnrpc.MacaroonPermission{
			{Entity: "address", Action: "read"}, {Entity: "address", Action: "write"},
			{Entity: "info", Action: "read"},
			{Entity: "invoices", Action: "read"}, {Entity: "invoices", Action: "write"},
			{Entity: "offchain", Action: "read"}, {Entity: "offchain", Action: "write"},
			{Entity: "onchain", Action: "read"}, {Entity: "onchain", Action: "write"},
			{Entity: "peers", Action: "read"}, {Entity: "peers", Action: "write"},
			{Entity: "signer", Action: "generate"}, {Entity: "signer", Action: "read"},
		},
	}
	_, err = mainServer.BakeMacaroon(context.Background(), bakeReq)
	if err != nil {
		log.Fatalf("failed to bake macaroon on startup: %v", err)
	}

	// --- Start Listening ---
	lis, err := net.Listen("tcp", ":10009")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Println("🚀 Mock LND gRPC Server is running securely with TLS on port :10009")
	grpcServer.Serve(lis)
}

// Helper function to generate certs if they don't exist
func generateCerts() error {
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "3650", "-nodes", "-keyout", "tls.key", "-out", "tls.cert", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	err := cmd.Run()
	if err != nil {
		log.Printf("Please install openssl or generate tls.cert and tls.key manually.")
		return err
	}
	return nil
}
