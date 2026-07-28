// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library XIRTypes {
    uint8 internal constant EVM = 1;
    uint8 internal constant SOLANA = 2;

    struct TypedId {
        uint8 kind;
        bytes value;
    }

    struct Record {
        TypedId sourceGateway;
        TypedId sourceApp;
        TypedId destinationApp;
        uint64 nonce;
        bytes32 payloadHash;
    }

    struct VerifiedContext {
        uint8 requiredSecurity;
        bytes32 policyHash;
    }

    struct RootCertificate {
        uint32 registryVersion;
        bytes signature;
    }

    struct Receipt {
        TypedId srcGateway;
        TypedId dstGateway;
        bytes32 profileHash;
        bytes32 evidenceHash;
        bytes32 transitionHash;
        bytes32 priorPrefix;
    }

    struct Envelope {
        Record record;
        VerifiedContext context;
        RootCertificate certificate;
        Receipt[] receipts;
    }
}
