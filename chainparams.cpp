#include "chainparams.h"

static CChainParams *pCurrentParams = 0;

const CChainParams &Params()
{
    if(pCurrentParams == 0)
        pCurrentParams = new CChainParams();
    return *pCurrentParams;
}

CChainParams::CChainParams()
{
    consensus.nSubsidyHalvingInterval = 210000;
    consensus.BIP34Height = 227931;
    consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
    consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
    consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
    consensus.powLimit = uint256S("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    consensus.nPowTargetTimespan =  100 * 60; // two weeks
    consensus.nPowTargetSpacing = 1 * 60;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fPowNoRetargeting = false;
    consensus.nRuleChangeActivationThreshold = 95; // 95% of 2016
    consensus.nMinerConfirmationWindow = 100; // nPowTargetTimespan / nPowTargetSpacing
    consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
    consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
    consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

    // Deployment of BIP68, BIP112, and BIP113.
    consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
    consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
    consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

    // Deployment of SegWit (BIP141, BIP143, and BIP147)
    consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
    consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
    consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

    // The best chain should have at least this much work.
    //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000003f94d1ad391682fe038bf5");
    //consensus.nMinimumChainWork = uint256S("0x00000fff6882ce28be9e7d838b5156ce320657cb87707ae1b16fde40c00f629d");
    consensus.nMinimumChainWork = uint256S("0x00");
    // By default assume that the signatures in ancestors of this block are valid.
    //consensus.defaultAssumeValid = uint256S("0x00000000000000000013176bf8d7dfeab4e1db31dc93bc311b436e82ab226b90"); //453354
    consensus.defaultAssumeValid = uint256S("0x00"); //1079274

    base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
    base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
    // base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
    // base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
    base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
    base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};


    base58Prefixes[SPA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,90);
    base58Prefixes[WNS_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,91);
    base58Prefixes[WNA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,92);
    // for real-name
    base58Prefixes[REALNAME_ADDRESS] = std::vector<unsigned char>(1,93);
    base58Prefixes[REALNAME_SPA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,94);
    base58Prefixes[REALNAME_WNS_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,95);
    base58Prefixes[REALNAME_WNA_CONTRACT_ADDRESS] = std::vector<unsigned char>(1,96);

    pchMessageStart[0] = 0xf9;
    pchMessageStart[1] = 0xbe;
    pchMessageStart[2] = 0xb4;
    pchMessageStart[3] = 0xd9;
}
