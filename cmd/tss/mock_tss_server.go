package main

import (
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"

	"github.com/RWAs-labs/go-tss/blame"
	"github.com/RWAs-labs/go-tss/common"
	"github.com/RWAs-labs/go-tss/conversion"
	"github.com/RWAs-labs/go-tss/keygen"
	"github.com/RWAs-labs/go-tss/keysign"
)

type MockTssServer struct {
	failToStart   bool
	failToKeyGen  bool
	failToKeySign bool
}

func (mts *MockTssServer) Start() error {
	if mts.failToStart {
		return errors.New("you ask for it")
	}
	return nil
}

func (mts *MockTssServer) Stop() {
}

func (mts *MockTssServer) GetLocalPeerID() string {
	return conversion.GetRandomPeerID().String()
}

func (mts *MockTssServer) GetKnownPeers() []peer.AddrInfo {
	return []peer.AddrInfo{}
}

func (mts *MockTssServer) Keygen(_ keygen.Request) (keygen.Response, error) {
	if mts.failToKeyGen {
		return keygen.Response{}, errors.New("you ask for it")
	}
	return keygen.NewResponse(
		common.ECDSA,
		conversion.GetRandomPubKey(),
		"whatever",
		common.Success,
		blame.Blame{},
	), nil
}

func (mts *MockTssServer) KeygenAllAlgo(_ keygen.Request) ([]keygen.Response, error) {
	if mts.failToKeyGen {
		return []keygen.Response{{}}, errors.New("you ask for it")
	}
	return []keygen.Response{
		keygen.NewResponse(common.ECDSA, conversion.GetRandomPubKey(), "whatever", common.Success, blame.Blame{}),
		keygen.NewResponse(common.EdDSA, conversion.GetRandomPubKey(), "whatever", common.Success, blame.Blame{}),
	}, nil
}

func (mts *MockTssServer) KeySign(_ keysign.Request) (keysign.Response, error) {
	if mts.failToKeySign {
		return keysign.Response{}, errors.New("you ask for it")
	}
	newSig := keysign.NewSignature("", "", "", "")
	return keysign.NewResponse([]keysign.Signature{newSig}, common.Success, blame.Blame{}), nil
}
