package xir

import (
	"crypto/sha256"
	"fmt"
)

// TypedIDABI is the ABI tuple shape of XIRTypes.TypedId.
type TypedIDABI struct {
	Kind  uint8  `abi:"kind"`
	Value []byte `abi:"value"`
}

// RecordABI is the ABI tuple shape of XIRTypes.Record.
type RecordABI struct {
	SourceGateway  TypedIDABI `abi:"sourceGateway"`
	SourceApp      TypedIDABI `abi:"sourceApp"`
	DestinationApp TypedIDABI `abi:"destinationApp"`
	Nonce          uint64     `abi:"nonce"`
	PayloadHash    [32]byte   `abi:"payloadHash"`
}

// ContextABI is the ABI tuple shape of XIRTypes.VerifiedContext.
type ContextABI struct {
	RequiredSecurity uint8    `abi:"requiredSecurity"`
	PolicyHash       [32]byte `abi:"policyHash"`
}

// CertificateABI is the ABI tuple shape of XIRTypes.RootCertificate.
type CertificateABI struct {
	RegistryVersion uint32 `abi:"registryVersion"`
	Signature       []byte `abi:"signature"`
}

// ReceiptABI is the ABI tuple shape of XIRTypes.Receipt. The prefix is the
// final component, matching XIRTypes.sol and xir_trace.receipt_tuple.
type ReceiptABI struct {
	SourceGateway      TypedIDABI `abi:"srcGateway"`
	DestinationGateway TypedIDABI `abi:"dstGateway"`
	ProfileHash        [32]byte   `abi:"profileHash"`
	EvidenceHash       [32]byte   `abi:"evidenceHash"`
	TransitionHash     [32]byte   `abi:"transitionHash"`
	PriorPrefix        [32]byte   `abi:"priorPrefix"`
}

// EnvelopeABI is the ABI tuple shape of XIRTypes.Envelope.
type EnvelopeABI struct {
	Record      RecordABI      `abi:"record"`
	Context     ContextABI     `abi:"context"`
	Certificate CertificateABI `abi:"certificate"`
	Receipts    []ReceiptABI   `abi:"receipts"`
}

// MultihopPayloadABI is the ABI tuple shape of NativeMultihopPayload.Data.
type MultihopPayloadABI struct {
	AttemptID          [32]byte `abi:"attemptId"`
	Route              []byte   `abi:"route"`
	RouteSequence      uint64   `abi:"routeSequence"`
	ApplicationPayload []byte   `abi:"applicationPayload"`
}

// ABI returns the ABI shape of one typed identifier.
func (t TypedID) ABI() TypedIDABI {
	return TypedIDABI{Kind: t.Kind, Value: append([]byte(nil), t.Value...)}
}

// ABI returns the ABI shape of the record.
func (r Record) ABI() RecordABI {
	return RecordABI{
		SourceGateway:  r.SourceGateway.ABI(),
		SourceApp:      r.SourceApp.ABI(),
		DestinationApp: r.DestinationApp.ABI(),
		Nonce:          r.Nonce,
		PayloadHash:    r.PayloadHash,
	}
}

// ABI returns the ABI shape of the context.
func (c Context) ABI() ContextABI {
	return ContextABI{RequiredSecurity: c.RequiredSecurity, PolicyHash: c.PolicyHash}
}

// ABI returns the ABI shape of one receipt.
func (r Receipt) ABI() ReceiptABI {
	return ReceiptABI{
		SourceGateway:      r.SourceGateway.ABI(),
		DestinationGateway: r.DestinationGateway.ABI(),
		ProfileHash:        r.ProfileHash,
		EvidenceHash:       r.EvidenceHash,
		TransitionHash:     r.TransitionHash,
		PriorPrefix:        r.PriorPrefix,
	}
}

// ABI returns the ABI shape of the envelope as the XIR gateway expects it.
func (e Envelope) ABI() EnvelopeABI {
	receipts := make([]ReceiptABI, 0, len(e.Receipts))
	for _, receipt := range e.Receipts {
		receipts = append(receipts, receipt.ABI())
	}
	return EnvelopeABI{
		Record:  e.Record.ABI(),
		Context: e.Context.ABI(),
		Certificate: CertificateABI{
			RegistryVersion: e.RegistryVersion,
			Signature:       append([]byte(nil), e.Signature...),
		},
		Receipts: receipts,
	}
}

// PayloadSchedule is the application payload size schedule of a campaign
// profile (configs/native/native-multihop-switching-v1.json payload_schedule).
type PayloadSchedule struct {
	MinimumBytes    uint64
	SizeBucketCount uint64
	SizeStepBytes   uint64
}

// Size returns the application payload size of one route sequence.
func (s PayloadSchedule) Size(routeSequence uint64) (uint64, error) {
	if s.SizeBucketCount == 0 {
		return 0, fmt.Errorf("payload schedule bucket count is zero")
	}
	return s.MinimumBytes + (routeSequence%s.SizeBucketCount)*s.SizeStepBytes, nil
}

// ApplicationBytes expands the deterministic application payload of one
// attempt (src/xir_lab/native/multihop_runner.py _application_payload).
func ApplicationBytes(fixedSeed, phase string, routeSequence uint64, schedule PayloadSchedule) ([]byte, error) {
	size, err := schedule.Size(routeSequence)
	if err != nil {
		return nil, err
	}
	material := []byte(fmt.Sprintf("xir-multihop-v1:%s:%s:%d", fixedSeed, phase, routeSequence))
	application := make([]byte, 0, size+32)
	counter := uint32(0)
	for uint64(len(application)) < size {
		counterBytes := []byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)}
		digest := sha256.Sum256(append(append([]byte(nil), material...), counterBytes...))
		application = append(application, digest[:]...)
		counter++
	}
	return application[:size], nil
}

// ApplicationPayload builds the NativeMultihopPayload.Data tuple of one
// attempt, matching the Python runner's application payload encoding.
func ApplicationPayload(
	attemptID [32]byte, route string, routeSequence uint64, application []byte,
) MultihopPayloadABI {
	return MultihopPayloadABI{
		AttemptID:          attemptID,
		Route:              []byte(route),
		RouteSequence:      routeSequence,
		ApplicationPayload: append([]byte(nil), application...),
	}
}
