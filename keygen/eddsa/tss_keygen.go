package eddsa

import (
	"encoding/json"
	"sync"
	"time"

	bcrypto "github.com/bnb-chain/tss-lib/crypto"
	eddsakg "github.com/bnb-chain/tss-lib/eddsa/keygen"
	btss "github.com/bnb-chain/tss-lib/tss"
	tcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/RWAs-labs/go-tss/blame"
	"github.com/RWAs-labs/go-tss/common"
	"github.com/RWAs-labs/go-tss/config"
	"github.com/RWAs-labs/go-tss/conversion"
	"github.com/RWAs-labs/go-tss/keygen"
	"github.com/RWAs-labs/go-tss/logs"
	"github.com/RWAs-labs/go-tss/messages"
	"github.com/RWAs-labs/go-tss/p2p"
	"github.com/RWAs-labs/go-tss/storage"
)

type Keygen struct {
	logger          zerolog.Logger
	localNodePubKey string
	tssCommonStruct *common.TssCommon
	stopChan        chan struct{} // channel to indicate whether we should stop
	localParty      *btss.PartyID
	stateManager    storage.LocalStateManager
	commStopChan    chan struct{}
	p2pComm         *p2p.Communication
}

func New(
	localP2PID string,
	conf common.TssConfig,
	localNodePubKey string,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{},
	msgID string,
	stateManager storage.LocalStateManager,
	privateKey tcrypto.PrivKey,
	p2pComm *p2p.Communication,
	logger zerolog.Logger,
) *Keygen {
	logger = logger.With().Str(logs.Component, "keygen").Str(logs.MsgID, msgID).Logger()

	return &Keygen{
		logger:          logger,
		localNodePubKey: localNodePubKey,
		tssCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privateKey, 1, logger),
		stopChan:        stopChan,
		localParty:      nil,
		stateManager:    stateManager,
		commStopChan:    make(chan struct{}),
		p2pComm:         p2pComm,
	}
}

func (kg *Keygen) KeygenChannel() chan *p2p.Message {
	return kg.tssCommonStruct.TssMsg
}

func (kg *Keygen) Common() *common.TssCommon {
	return kg.tssCommonStruct
}

func (kg *Keygen) GenerateNewKey(req keygen.Request) (*bcrypto.ECPoint, error) {
	keyGenPartyMap := new(sync.Map)
	partiesID, localPartyID, err := conversion.GetParties(req.Keys, kg.localNodePubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get keygen parties")
	}

	keyGenLocalStateItem := storage.KeygenLocalState{
		ParticipantKeys: req.Keys,
		LocalPartyKey:   kg.localNodePubKey,
	}

	threshold, err := conversion.GetThreshold(len(partiesID))
	if err != nil {
		return nil, errors.Wrap(err, "failed to get threshold")
	}

	var (
		ctx         = btss.NewPeerContext(partiesID)
		params      = btss.NewParameters(btss.Edwards(), ctx, localPartyID, len(partiesID), threshold)
		outCh       = make(chan btss.Message, len(partiesID))
		endCh       = make(chan eddsakg.LocalPartySaveData, len(partiesID))
		errChan     = make(chan struct{})
		blameMgr    = kg.tssCommonStruct.GetBlameMgr()
		keyGenParty = eddsakg.NewLocalParty(params, outCh, endCh)
		partyIDMap  = conversion.SetupPartyIDMap(partiesID)
	)

	err = conversion.SetupIDMaps(partyIDMap, kg.tssCommonStruct.PartyIDtoP2PID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to setup ID maps #1")
	}

	err = conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to setup ID maps #2")
	}

	keyGenPartyMap.Store("", keyGenParty)
	partyInfo := &common.PartyInfo{
		PartyMap:   keyGenPartyMap,
		PartyIDMap: partyIDMap,
	}

	kg.tssCommonStruct.SetPartyInfo(partyInfo)
	blameMgr.SetPartyInfo(keyGenPartyMap, partyIDMap)
	kg.tssCommonStruct.P2PPeersLock.Lock()
	kg.tssCommonStruct.P2PPeers = conversion.GetPeersID(
		kg.tssCommonStruct.PartyIDtoP2PID,
		kg.tssCommonStruct.GetLocalPeerID(),
	)
	kg.tssCommonStruct.P2PPeersLock.Unlock()

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)

	// start keygen
	go func() {
		defer keyGenWg.Done()
		defer kg.logger.Debug().Msg("keyGenParty started")
		if err := keyGenParty.Start(); nil != err {
			kg.logger.Error().Err(err).Msg("fail to start keygen party")
			close(errChan)
		}
	}()

	go kg.tssCommonStruct.ProcessInboundMessages(kg.commStopChan, &keyGenWg)

	r, err := kg.processKeyGen(errChan, outCh, endCh, keyGenLocalStateItem)
	if err != nil {
		close(kg.commStopChan)
		return nil, errors.Wrap(err, "failed to process key gen")
	}

	select {
	case <-time.After(config.TSSCommonFinalTimeout):
		close(kg.commStopChan)
	case <-kg.tssCommonStruct.GetTaskDone():
		close(kg.commStopChan)
	}

	keyGenWg.Wait()

	return r, err
}

func (kg *Keygen) processKeyGen(
	errChan chan struct{},
	outCh <-chan btss.Message,
	endCh <-chan eddsakg.LocalPartySaveData,
	keyGenLocalStateItem storage.KeygenLocalState,
) (*bcrypto.ECPoint, error) {
	defer kg.logger.Debug().Msg("finished keygen process")
	kg.logger.Debug().Msg("start to read messages from local party")
	tssConf := kg.tssCommonStruct.GetConf()
	blameMgr := kg.tssCommonStruct.GetBlameMgr()
	for {
		select {
		case <-errChan: // when keyGenParty return
			kg.logger.Error().Msg("key gen failed")
			return nil, errors.New("error channel closed fail to start local party")

		case <-kg.stopChan: // when TSS processor receive signal to quit
			return nil, errors.New("received exit signal")

		case <-time.After(tssConf.KeyGenTimeout):
			// we bail out after KeyGenTimeoutSeconds
			kg.logger.Error().Msgf("fail to generate message with %s", tssConf.KeyGenTimeout.String())
			lastMsg := blameMgr.GetLastMsg()
			failReason := blameMgr.GetBlame().FailReason
			if failReason == "" {
				failReason = blame.TssTimeout
			}
			if lastMsg == nil {
				kg.logger.Error().Msg("fail to start the keygen, the last produced message of this node is none")
				return nil, errors.New("timeout before shared message is generated")
			}
			blameNodesUnicast, err := blameMgr.GetUnicastBlame(messages.KEYGEN2aUnicast)
			if err != nil {
				kg.logger.Error().Err(err).Msg("error in get unicast blame")
			}
			threshold, err := conversion.GetThreshold(len(kg.tssCommonStruct.P2PPeers) + 1)
			if err != nil {
				kg.logger.Error().Err(err).Msg("error in get the threshold to generate blame")
			}

			if len(blameNodesUnicast) > 0 && len(blameNodesUnicast) <= threshold {
				blameMgr.GetBlame().SetBlame(failReason, blameNodesUnicast, lastMsg.IsBroadcast(), lastMsg.Type())
			}
			blameNodesBroadcast, err := blameMgr.GetBroadcastBlame(lastMsg.Type())
			if err != nil {
				kg.logger.Error().Err(err).Msg("error in get broadcast blame")
			}
			blameMgr.GetBlame().AddBlameNodes(blameNodesBroadcast...)

			// if we cannot find the blame node, we check whether everyone send me the share
			if len(blameMgr.GetBlame().BlameNodes) == 0 {
				blameNodesMisingShare, isUnicast, err := blameMgr.TSSMissingShareBlame(
					messages.EDDSAKEYGENROUNDS,
					messages.EDDSAKEYGEN,
				)
				if err != nil {
					kg.logger.Error().Err(err).Msg("fail to get the node of missing share ")
				}
				if len(blameNodesMisingShare) > 0 && len(blameNodesMisingShare) <= threshold {
					blameMgr.GetBlame().AddBlameNodes(blameNodesMisingShare...)
					blameMgr.GetBlame().IsUnicast = isUnicast
				}
			}
			return nil, blame.ErrTimeoutTSS

		case msg := <-outCh:
			kg.logger.Debug().Msgf(">>>>>>>>>>msg: %s", msg.String())
			blameMgr.SetLastMsg(msg)
			err := kg.tssCommonStruct.ProcessOutCh(msg, messages.TSSKeyGenMsg)
			if err != nil {
				kg.logger.Error().Err(err).Msg("fail to process the message")
				return nil, err
			}

		case msg := <-endCh:
			kg.logger.Debug().Msgf("keygen finished successfully: %s", msg.EDDSAPub.Y().String())
			err := kg.tssCommonStruct.NotifyTaskDone()
			if err != nil {
				kg.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
			}
			pubKey, _, err := conversion.GetTssPubKeyEDDSA(msg.EDDSAPub)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get thorchain pubkey")
			}
			marshaledMsg, err := json.Marshal(msg)
			if err != nil {
				kg.logger.Error().Err(err).Msg("fail to marshal the result")
				return nil, errors.New("fail to marshal the result")
			}
			keyGenLocalStateItem.LocalData = marshaledMsg
			keyGenLocalStateItem.PubKey = pubKey
			if err := kg.stateManager.SaveLocalState(keyGenLocalStateItem); err != nil {
				return nil, errors.Wrap(err, "failed to save keygen result to storage")
			}
			address := kg.p2pComm.ExportPeerAddress()
			if err := kg.stateManager.SaveAddressBook(address); err != nil {
				kg.logger.Error().Err(err).Msg("fail to save the peer addresses")
			}
			return msg.EDDSAPub, nil
		}
	}
}
