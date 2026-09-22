package xir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lysrain21/XIR/go-runtime/internal/abiutil"
)

type vectorDocument struct {
	SchemaVersion string `json:"schema_version"`
	Constants     struct {
		RegistryVersion uint32 `json:"registry_version"`
		PayloadSchedule struct {
			MinimumBytes    uint64 `json:"minimum_bytes"`
			SizeBucketCount uint64 `json:"size_bucket_count"`
			SizeStepBytes   uint64 `json:"size_step_bytes"`
		} `json:"payload_schedule"`
		FixedSeed   string            `json:"fixed_seed"`
		FixtureKeys map[string]string `json:"fixture_keys"`
		ChainIDs    []uint64          `json:"chain_ids"`
		Routes      []string          `json:"routes"`
	} `json:"constants"`
	ProfileHashes []struct {
		Route    string `json:"route"`
		HopIndex int    `json:"hop_index"`
		Hash     string `json:"hash"`
	} `json:"profile_hashes"`
	GatewayTypedIDs []struct {
		ChainID uint64 `json:"chain_id"`
		Kind    uint8  `json:"kind"`
		Value   string `json:"value"`
	} `json:"gateway_typed_ids"`
	AdapterKeys []struct {
		Route     string `json:"route"`
		HopIndex  int    `json:"hop_index"`
		Direction string `json:"direction"`
		Key       string `json:"key"`
	} `json:"adapter_keys"`
	TypedIDs []struct {
		Kind  uint8  `json:"kind"`
		Value string `json:"value"`
		Hash  string `json:"hash"`
	} `json:"typed_ids"`
	BundleSteps []struct {
		Index          int    `json:"index"`
		ReceiptCount   int    `json:"receipt_count"`
		BundleStart    string `json:"bundle_start"`
		Step           string `json:"step"`
		ProfileHash    string `json:"profile_hash"`
		EvidenceHash   string `json:"evidence_hash"`
		TransitionHash string `json:"transition_hash"`
	} `json:"bundle_steps"`
	Payloads []struct {
		AttemptID         string `json:"attempt_id"`
		Phase             string `json:"phase"`
		Route             string `json:"route"`
		RouteSequence     uint64 `json:"route_sequence"`
		AttemptKey        string `json:"attempt_key"`
		ApplicationSHA256 string `json:"application_sha256"`
		ApplicationBytes  string `json:"application_bytes"`
		PayloadEncoding   string `json:"payload_encoding"`
	} `json:"payloads"`
	Envelopes []struct {
		Seed   int `json:"seed"`
		Record struct {
			SourceGateway  string `json:"source_gateway"`
			SourceApp      string `json:"source_app"`
			DestinationApp string `json:"destination_app"`
			Nonce          uint64 `json:"nonce"`
			PayloadHash    string `json:"payload_hash"`
		} `json:"record"`
		Context struct {
			RequiredSecurity uint8  `json:"required_security"`
			PolicyHash       string `json:"policy_hash"`
		} `json:"context"`
		RID              string   `json:"rid"`
		MID              string   `json:"mid"`
		RootPrefix       string   `json:"root_prefix"`
		TransitionHashes []string `json:"transition_hashes"`
		Receipts         []struct {
			SourceGateway      string `json:"source_gateway"`
			DestinationGateway string `json:"destination_gateway"`
			ProfileHash        string `json:"profile_hash"`
			EvidenceHash       string `json:"evidence_hash"`
			TransitionHash     string `json:"transition_hash"`
			PriorPrefix        string `json:"prior_prefix"`
			ReceiptHash        string `json:"receipt_hash"`
			NextPrefix         string `json:"next_prefix"`
		} `json:"receipts"`
		BundleCommitment string `json:"bundle_commitment"`
		RootSignature    string `json:"root_signature"`
		EnvelopeEncoding string `json:"envelope_encoding"`
		RecordHash       string `json:"record_hash"`
		ContextHash      string `json:"context_hash"`
	} `json:"envelopes"`
}

// payloadArgumentJSON and envelopeArgumentJSON restate the Solidity tuple
// types of NativeMultihopPayload.Data and XIRTypes.Envelope. The vector file
// pins the bytes both references produce, so a shape error fails the test.
const payloadArgumentJSON = `{"name":"payload","type":"tuple","components":[` +
	`{"name":"attemptId","type":"bytes32"},{"name":"route","type":"bytes"},` +
	`{"name":"routeSequence","type":"uint64"},{"name":"applicationPayload","type":"bytes"}]}`

const typedIDComponents = `{"name":"kind","type":"uint8"},{"name":"value","type":"bytes"}`

const envelopeArgumentJSON = `{"name":"envelope","type":"tuple","components":[` +
	`{"name":"record","type":"tuple","components":[` +
	`{"name":"sourceGateway","type":"tuple","components":[` + typedIDComponents + `]},` +
	`{"name":"sourceApp","type":"tuple","components":[` + typedIDComponents + `]},` +
	`{"name":"destinationApp","type":"tuple","components":[` + typedIDComponents + `]},` +
	`{"name":"nonce","type":"uint64"},{"name":"payloadHash","type":"bytes32"}]},` +
	`{"name":"context","type":"tuple","components":[` +
	`{"name":"requiredSecurity","type":"uint8"},{"name":"policyHash","type":"bytes32"}]},` +
	`{"name":"certificate","type":"tuple","components":[` +
	`{"name":"registryVersion","type":"uint32"},{"name":"signature","type":"bytes"}]},` +
	`{"name":"receipts","type":"tuple[]","components":[` +
	`{"name":"srcGateway","type":"tuple","components":[` + typedIDComponents + `]},` +
	`{"name":"dstGateway","type":"tuple","components":[` + typedIDComponents + `]},` +
	`{"name":"profileHash","type":"bytes32"},{"name":"evidenceHash","type":"bytes32"},` +
	`{"name":"transitionHash","type":"bytes32"},{"name":"priorPrefix","type":"bytes32"}]}]}`

func loadVectors(t *testing.T) vectorDocument {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read parity vectors: %v", err)
	}
	var document vectorDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode parity vectors: %v", err)
	}
	if document.SchemaVersion != "xir-go-parity-vectors-v1" {
		t.Fatalf("unexpected vector schema: %q", document.SchemaVersion)
	}
	return document
}

func digest(t *testing.T, value string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(trimHex(value))
	if err != nil {
		t.Fatalf("decode digest %q: %v", value, err)
	}
	if len(raw) != 32 {
		t.Fatalf("digest %q is %d bytes", value, len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func trimHex(value string) string {
	if len(value) >= 2 && value[:2] == "0x" {
		return value[2:]
	}
	return value
}

func TestTypedIDVectors(t *testing.T) {
	document := loadVectors(t)
	for _, vector := range document.TypedIDs {
		value, err := hex.DecodeString(trimHex(vector.Value))
		if err != nil {
			t.Fatalf("decode typed id value: %v", err)
		}
		id := TypedID{Kind: vector.Kind, Value: value}
		encoded, err := id.Bytes()
		if err != nil {
			t.Fatalf("encode typed id: %v", err)
		}
		wantEncoded := append([]byte{vector.Kind, byte(len(value))}, value...)
		if string(encoded) != string(wantEncoded) {
			t.Fatalf("typed id encoding mismatch: %x != %x", encoded, wantEncoded)
		}
		hash, err := id.Hash()
		if err != nil {
			t.Fatalf("hash typed id: %v", err)
		}
		if hash != digest(t, vector.Hash) {
			t.Fatalf("typed id hash mismatch for %s", vector.Value)
		}
	}
}

func TestProfileAndDeploymentIdentityVectors(t *testing.T) {
	document := loadVectors(t)
	for _, vector := range document.ProfileHashes {
		hash, err := ProfileHash(vector.Route, vector.HopIndex)
		if err != nil {
			t.Fatalf("profile hash: %v", err)
		}
		if hash != digest(t, vector.Hash) {
			t.Fatalf("profile hash mismatch for %s hop %d", vector.Route, vector.HopIndex)
		}
	}
	for _, vector := range document.GatewayTypedIDs {
		id, err := GatewayTypedID(vector.ChainID)
		if err != nil {
			t.Fatalf("gateway typed id: %v", err)
		}
		if id.Kind != vector.Kind || hex.EncodeToString(id.Value) != trimHex(vector.Value) {
			t.Fatalf("gateway typed id mismatch for chain %d", vector.ChainID)
		}
	}
	for _, vector := range document.AdapterKeys {
		key, err := AdapterKey(vector.Route, vector.HopIndex, vector.Direction)
		if err != nil {
			t.Fatalf("adapter key: %v", err)
		}
		if key != vector.Key {
			t.Fatalf("adapter key mismatch: %q != %q", key, vector.Key)
		}
	}
}

func TestApplicationPayloadVectors(t *testing.T) {
	document := loadVectors(t)
	schedule := PayloadSchedule{
		MinimumBytes:    document.Constants.PayloadSchedule.MinimumBytes,
		SizeBucketCount: document.Constants.PayloadSchedule.SizeBucketCount,
		SizeStepBytes:   document.Constants.PayloadSchedule.SizeStepBytes,
	}
	for _, vector := range document.Payloads {
		application, err := ApplicationBytes(
			document.Constants.FixedSeed, vector.Phase, vector.RouteSequence, schedule,
		)
		if err != nil {
			t.Fatalf("application bytes: %v", err)
		}
		if hex.EncodeToString(application) != trimHex(vector.ApplicationBytes) {
			t.Fatalf("application payload mismatch for %s", vector.AttemptID)
		}
		attemptKey := Keccak256([]byte(vector.AttemptID))
		if digest(t, vector.AttemptKey) != attemptKey {
			t.Fatalf("attempt key mismatch for %s", vector.AttemptID)
		}
		payload := ApplicationPayload(attemptKey, vector.Route, vector.RouteSequence, application)
		encoded, err := abiutil.PackArgument(payloadArgumentJSON, payload)
		if err != nil {
			t.Fatalf("pack multihop payload: %v", err)
		}
		if hex.EncodeToString(encoded) != trimHex(vector.PayloadEncoding) {
			t.Fatalf("multihop payload encoding mismatch for %s", vector.AttemptID)
		}
	}
}

func TestEnvelopeVectors(t *testing.T) {
	document := loadVectors(t)
	for _, vector := range document.Envelopes {
		record := Record{
			SourceGateway:  TypedID{Kind: KindEVM, Value: mustHex(t, vector.Record.SourceGateway)},
			SourceApp:      TypedID{Kind: KindEVM, Value: mustHex(t, vector.Record.SourceApp)},
			DestinationApp: TypedID{Kind: KindEVM, Value: mustHex(t, vector.Record.DestinationApp)},
			Nonce:          vector.Record.Nonce,
			PayloadHash:    digest(t, vector.Record.PayloadHash),
		}
		context := Context{
			RequiredSecurity: vector.Context.RequiredSecurity,
			PolicyHash:       digest(t, vector.Context.PolicyHash),
		}
		recordHash, err := record.Hash()
		if err != nil {
			t.Fatalf("record hash: %v", err)
		}
		if recordHash != digest(t, vector.RecordHash) {
			t.Fatalf("record hash mismatch: %s", FormatDigest(recordHash))
		}
		if context.Hash() != digest(t, vector.ContextHash) {
			t.Fatalf("context hash mismatch")
		}
		rid, err := RootID(record, context, document.Constants.RegistryVersion)
		if err != nil {
			t.Fatalf("root id: %v", err)
		}
		if rid != digest(t, vector.RID) {
			t.Fatalf("rid mismatch: %s != %s", FormatDigest(rid), vector.RID)
		}
		mid, err := MessageID(rid, record.DestinationApp)
		if err != nil {
			t.Fatalf("message id: %v", err)
		}
		if mid != digest(t, vector.MID) {
			t.Fatalf("mid mismatch: %s != %s", FormatDigest(mid), vector.MID)
		}
		if RootPrefix(rid) != digest(t, vector.RootPrefix) {
			t.Fatalf("root prefix mismatch")
		}
		receipts := make([]Receipt, 0, len(vector.Receipts))
		for index, item := range vector.Receipts {
			receipt := Receipt{
				SourceGateway:      TypedID{Kind: KindEVM, Value: mustHex(t, item.SourceGateway)},
				DestinationGateway: TypedID{Kind: KindEVM, Value: mustHex(t, item.DestinationGateway)},
				ProfileHash:        digest(t, item.ProfileHash),
				EvidenceHash:       digest(t, item.EvidenceHash),
				TransitionHash:     digest(t, item.TransitionHash),
				PriorPrefix:        digest(t, item.PriorPrefix),
			}
			if len(receipts) == 0 {
				if receipt.PriorPrefix != RootPrefix(rid) {
					t.Fatalf("receipt %d prefix is not the root prefix", index)
				}
			} else {
				prior, err := NextPrefix(receipts[len(receipts)-1].PriorPrefix, receipts[len(receipts)-1])
				if err != nil {
					t.Fatalf("next prefix: %v", err)
				}
				if receipt.PriorPrefix != prior {
					t.Fatalf("receipt %d prefix does not extend its predecessor", index)
				}
			}
			transition, err := TransitionHash(record, context, receipt.SourceGateway, receipt.DestinationGateway)
			if err != nil {
				t.Fatalf("transition hash: %v", err)
			}
			if transition != digest(t, vector.TransitionHashes[index]) {
				t.Fatalf("transition hash mismatch at %d", index)
			}
			if transition != receipt.TransitionHash {
				t.Fatalf("receipt %d transition differs from derivation", index)
			}
			receiptHash, err := receipt.Hash()
			if err != nil {
				t.Fatalf("receipt hash: %v", err)
			}
			if receiptHash != digest(t, item.ReceiptHash) {
				t.Fatalf("receipt hash mismatch at %d", index)
			}
			next, _ := NextPrefix(receipt.PriorPrefix, receipt)
			if next != digest(t, item.NextPrefix) {
				t.Fatalf("next prefix mismatch at %d", index)
			}
			receipts = append(receipts, receipt)
		}
		if BundleCommitment(receipts) != digest(t, vector.BundleCommitment) {
			t.Fatalf("bundle commitment mismatch")
		}
		envelope := Envelope{
			Record:          record,
			Context:         context,
			RegistryVersion: document.Constants.RegistryVersion,
			Signature:       mustHex(t, vector.RootSignature),
			Receipts:        receipts,
		}
		if len(envelope.Signature) != 65 {
			t.Fatalf("root signature is %d bytes", len(envelope.Signature))
		}
		encoded, err := abiutil.PackArgument(envelopeArgumentJSON, envelope.ABI())
		if err != nil {
			t.Fatalf("pack envelope: %v", err)
		}
		if hex.EncodeToString(encoded) != trimHex(vector.EnvelopeEncoding) {
			t.Fatalf("envelope ABI encoding mismatch for seed %d", vector.Seed)
		}
	}
}

func TestBundleStepVectors(t *testing.T) {
	document := loadVectors(t)
	if len(document.BundleSteps) == 0 {
		t.Fatal("bundle step vectors are empty")
	}
	for _, vector := range document.BundleSteps {
		receipt := Receipt{
			ProfileHash:    digest(t, vector.ProfileHash),
			EvidenceHash:   digest(t, vector.EvidenceHash),
			TransitionHash: digest(t, vector.TransitionHash),
		}
		if BundleStart(vector.ReceiptCount) != digest(t, vector.BundleStart) {
			t.Fatalf("bundle start mismatch at %d", vector.Index)
		}
		step := BundleStep(BundleStart(vector.ReceiptCount), vector.Index, receipt)
		if step != digest(t, vector.Step) {
			t.Fatalf("bundle step mismatch at %d", vector.Index)
		}
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(trimHex(value))
	if err != nil {
		t.Fatalf("decode %q: %v", value, err)
	}
	return raw
}
