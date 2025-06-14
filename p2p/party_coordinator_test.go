package p2p

import (
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	tnet "github.com/libp2p/go-libp2p-testing/net"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/RWAs-labs/go-tss/conversion"
)

func setupHosts(t *testing.T, n int) []host.Host {
	mn := mocknet.New()

	var hosts []host.Host

	for range n {
		id := tnet.RandIdentityOrFatal(t)
		a := tnet.RandLocalTCPAddress()

		h, err := mn.AddPeer(id.PrivateKey(), a)
		require.NoError(t, err)

		hosts = append(hosts, h)
	}

	assert.NoError(t, mn.LinkAll())
	assert.NoError(t, mn.ConnectAllButSelf())

	return hosts
}

func leaderAppearsLastTest(t *testing.T, msgID string, peers []peer.ID, pcs []*PartyCoordinator) {
	wg := sync.WaitGroup{}

	for _, el := range pcs[1:] {
		wg.Add(1)
		go func(coordinator *PartyCoordinator) {
			defer wg.Done()
			// we simulate different nodes join at different time
			time.Sleep(time.Millisecond * time.Duration(rand.Int()%100))
			sigChan := make(chan string)
			onlinePeers, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
			assert.NoError(t, err)
			assert.Len(t, onlinePeers, 4)
		}(el)
	}

	time.Sleep(time.Second * 2)
	// we start the leader firstly
	wg.Add(1)
	go func(coordinator *PartyCoordinator) {
		defer wg.Done()
		sigChan := make(chan string)
		// we simulate different nodes join at different time
		onlinePeers, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
		assert.NoError(t, err)
		assert.Len(t, onlinePeers, 4)
	}(pcs[0])
	wg.Wait()
}

func leaderAppearsFirstTest(t *testing.T, msgID string, peers []peer.ID, pcs []*PartyCoordinator) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	// we start the leader firstly
	go func(coordinator *PartyCoordinator) {
		defer wg.Done()
		// we simulate different nodes join at different time
		sigChan := make(chan string)
		onlinePeers, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
		assert.NoError(t, err)
		assert.Len(t, onlinePeers, 4)
	}(pcs[0])
	time.Sleep(time.Second)
	for _, el := range pcs[1:] {
		wg.Add(1)
		go func(coordinator *PartyCoordinator) {
			defer wg.Done()
			// we simulate different nodes join at different time
			time.Sleep(time.Millisecond * time.Duration(rand.Int()%100))
			sigChan := make(chan string)
			onlinePeers, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
			assert.NoError(t, err)
			assert.Len(t, onlinePeers, 4)
		}(el)
	}
	wg.Wait()
}

func TestNewPartyCoordinator(t *testing.T) {
	log := logger("TestNewPartyCoordinator")

	hosts := setupHosts(t, 4)
	var pcs []*PartyCoordinator
	var peers []peer.ID

	timeout := time.Second * 4
	for _, el := range hosts {
		pcs = append(pcs, NewPartyCoordinator(el, timeout, log))
		peers = append(peers, el.ID())
	}

	defer func() {
		for _, el := range pcs {
			el.Stop()
		}
	}()

	msgID := conversion.RandStringBytesMask(64)
	leader, err := PickLeader(msgID, 10, peers)
	assert.NoError(t, err)

	// we sort the slice to ensure the leader is the first one easy for testing
	for i, el := range pcs {
		if el.host.ID() == leader {
			if i == 0 {
				break
			}
			temp := pcs[0]
			pcs[0] = el
			pcs[i] = temp
			break
		}
	}
	assert.Equal(t, pcs[0].host.ID(), leader)
	// now we test the leader appears firstly and the the members
	leaderAppearsFirstTest(t, msgID, peers, pcs)
	leaderAppearsLastTest(t, msgID, peers, pcs)
}

func TestNewPartyCoordinatorTimeOut(t *testing.T) {
	log := logger("PartyCoordinatorTimeOut")

	timeout := time.Second * 3
	hosts := setupHosts(t, 4)
	var pcs []*PartyCoordinator
	var peers []peer.ID
	for _, el := range hosts {
		pcs = append(pcs, NewPartyCoordinator(el, timeout, log))
	}
	sort.Slice(pcs, func(i, j int) bool {
		return pcs[i].host.ID().String() > pcs[j].host.ID().String()
	})
	for _, el := range pcs {
		peers = append(peers, el.host.ID())
	}

	defer func() {
		for _, el := range pcs {
			el.Stop()
		}
	}()

	msgID := conversion.RandStringBytesMask(64)
	wg := sync.WaitGroup{}
	leader, err := PickLeader(msgID, 10, peers)
	assert.NoError(t, err)

	// we sort the slice to ensure the leader is the first one easy for testing
	for i, el := range pcs {
		if el.host.ID() == leader {
			if i == 0 {
				break
			}
			temp := pcs[0]
			pcs[0] = el
			pcs[i] = temp
			break
		}
	}
	assert.Equal(t, pcs[0].host.ID(), leader)

	// we test the leader is offline
	for _, el := range pcs[1:] {
		wg.Add(1)
		go func(coordinator *PartyCoordinator) {
			defer wg.Done()
			sigChan := make(chan string)
			_, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
			assert.ErrorIs(t, err, ErrLeaderNotReady)
		}(el)

	}
	wg.Wait()
	// we test one of node is not ready
	var expected []string
	for _, el := range pcs[:3] {
		expected = append(expected, el.host.ID().String())
		sort.Strings(expected)
		wg.Add(1)
		go func(coordinator *PartyCoordinator) {
			defer wg.Done()
			sigChan := make(chan string)
			onlinePeers, _, err := coordinator.JoinPartyWithLeader(msgID, 10, peers, 3, sigChan)
			assert.ErrorIs(t, err, ErrJoinPartyTimeout)
			var onlinePeersStr []string
			for _, el := range onlinePeers {
				onlinePeersStr = append(onlinePeersStr, el.String())
			}
			sort.Strings(onlinePeersStr)
			sort.Strings(expected[:3])
			assert.EqualValues(t, expected, onlinePeersStr)
		}(el)
	}
	wg.Wait()
}

func TestGetPeerIDs(t *testing.T) {
	log := logger("TestGetPeerIDs")

	id1 := tnet.RandIdentityOrFatal(t)
	mn := mocknet.New()
	// add peers to mock net

	a1 := tnet.RandLocalTCPAddress()
	h1, err := mn.AddPeer(id1.PrivateKey(), a1)
	require.NoError(t, err)

	p1 := h1.ID()
	timeout := time.Second * 2
	pc := NewPartyCoordinator(h1, timeout, log)
	r, err := pc.getPeerIDs([]string{})
	assert.NoError(t, err)
	assert.Len(t, r, 0)
	input := []string{
		p1.String(),
	}
	r1, err := pc.getPeerIDs(input)
	assert.NoError(t, err)
	assert.Len(t, r1, 1)
	assert.Equal(t, r1[0], p1)
	input = append(input, "whatever")

	_, err = pc.getPeerIDs(input)
	assert.Error(t, err)
}
