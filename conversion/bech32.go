package conversion

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func SetupBech32Prefix() {
	config := sdk.GetConfig()
	// musechain will import go-tss as a library , thus this is not needed, we copy the prefix here to avoid go-tss to import musechain
	config.SetBech32PrefixForAccount("muse", "musepub")
	config.SetBech32PrefixForValidator("musev", "musevpub")
	config.SetBech32PrefixForConsensusNode("musec", "musecpub")
}
