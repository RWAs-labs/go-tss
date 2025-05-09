package keysign

import (
	bc "github.com/bnb-chain/tss-lib/common"

	"github.com/RWAs-labs/go-tss/common"
	"github.com/RWAs-labs/go-tss/p2p"
	"github.com/RWAs-labs/go-tss/storage"
)

type TssKeySign interface {
	GetTssKeySignChannels() chan *p2p.Message
	GetTssCommonStruct() *common.TssCommon
	SignMessage(
		msgToSign [][]byte,
		localStateItem storage.KeygenLocalState,
		parties []string,
	) ([]*bc.SignatureData, error)
}
