use core::time::Duration;
use std::{io::ErrorKind, path::Path, sync::Arc};

use anyhow::{bail, Context as _, Result};
use deposit_tree::DepositTree;
use fork_choice_control::checkpoint_sync;
use genesis::GenesisProvider;
use p2p::{Enr, NetworkConfig};
use reqwest::{Client, Url};
use ssz::SszRead as _;
use strum::Display;
use tap::Pipe as _;
use types::{combined::BeaconState, config::Config as ChainConfig, preset::Preset};

#[cfg(any(
    feature = "network-mainnet",
    feature = "network-medalla",
    feature = "network-pyrmont",
    test,
))]
use ::{hex_literal::hex, types::phase0::primitives::H256};

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum PredefinedNetwork {
    #[cfg(any(feature = "network-mainnet", test))]
    Mainnet,
    #[cfg(any(feature = "network-medalla", test))]
    Medalla,
    #[cfg(any(feature = "network-pyrmont", test))]
    Pyrmont,
    #[cfg(any(feature = "network-goerli", test))]
    Goerli,
    #[cfg(any(feature = "network-kintsugi", test))]
    Kintsugi,
    #[cfg(any(feature = "network-kiln", test))]
    Kiln,
    #[cfg(any(feature = "network-ropsten", test))]
    Ropsten,
    #[cfg(any(feature = "network-sepolia", test))]
    Sepolia,
    #[cfg(any(feature = "network-withdrawals", test))]
    Withdrawals,
    #[cfg(any(feature = "network-holesky", test))]
    Holesky,
}

impl PredefinedNetwork {
    /// [Mainnet bootnode ENRs](https://github.com/eth-clients/eth2-networks/blob/7433deff7655559078cf60bb67caaaace67fe52b/shared/mainnet/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-mainnet", test))]
    pub const MAINNET_BOOTNODES: &'static [&'static str] = &[
        // > Teku team's bootnodes
        "enr:-KG4QNTx85fjxABbSq_Rta9wy56nQ1fHK0PewJbGjLm1M4bMGx5-3Qq4ZX2-iFJ0pys_O90sVXNNOxp2E7afBsGsBrgDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaECGXWQ-rQ2KZKRH1aOW4IlPDBkY4XDphxg9pxKytFCkayDdGNwgiMog3VkcIIjKA",
        "enr:-KG4QF4B5WrlFcRhUU6dZETwY5ZzAXnA0vGC__L1Kdw602nDZwXSTs5RFXFIFUnbQJmhNGVU6OIX7KVrCSTODsz1tK4DhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQExNYEiXNlY3AyNTZrMaECQmM9vp7KhaXhI-nqL_R0ovULLCFSFTa9CPPSdb1zPX6DdGNwgiMog3VkcIIjKA",

        // > Prylab team's bootnodes
        "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
        "enr:-Ku4QP2xDnEtUXIjzJ_DhlCRN9SN99RYQPJL92TMlSv7U5C1YnYLjwOQHgZIUXw6c-BvRg2Yc2QsZxxoS_pPRVe0yK8Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMeFF5GrS7UZpAH2Ly84aLK-TyvH-dRo0JM1i8yygH50YN1ZHCCJxA",
        "enr:-Ku4QPp9z1W4tAO8Ber_NQierYaOStqhDqQdOPY3bB3jDgkjcbk6YrEnVYIiCBbTxuar3CzS528d2iE7TdJsrL-dEKoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMw5fqqkw2hHC4F5HZZDPsNmPdB1Gi8JPQK7pRc9XHh-oN1ZHCCKvg",

        // > Lighthouse team's bootnodes
        "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
        "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
        "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
        "enr:-Le4QIqLuWybHNONr933Lk0dcMmAB5WgvGKRyDihy1wHDIVlNuuztX62W51voT4I8qD34GcTEOTmag1bcdZ_8aaT4NUBhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY04ng2lwNpAkAh8AgAIBAAAAAAAAAA-fiXNlY3AyNTZrMaEDscnRV6n1m-D9ID5UsURk0jsoKNXt1TIrj8uKOGW6iluDdWRwgiMohHVkcDaCI4I",

        // > EF bootnodes
        "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
        "enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg",
        "enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg",
        "enr:-Ku4QEWzdnVtXc2Q0ZVigfCGggOVB2Vc1ZCPEc6j21NIFLODSJbvNaef1g4PxhPwl_3kax86YPheFUSLXPRs98vvYsoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDZBrP2Jc2VjcDI1NmsxoQM6jr8Rb1ktLEsVcKAPa08wCsKUmvoQ8khiOl_SLozf9IN1ZHCCIyg",

        // > Nimbus team's bootnodes
        "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QKWrXTpV9T78hNG6s8AM6IO4XH9kFT91uZtFg1GcsJ6dKovDOr1jtAAFPnS2lvNltkOGA9k29BUN7lFh_sjuc9QBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhANAdd-Jc2VjcDI1NmsxoQLQa6ai7y9PMN5hpLe5HmiJSlYzMuzP7ZhwRiwHvqNXdoN0Y3CCI4yDdWRwgiOM",
    ];

    /// [Medalla bootnode ENRs](https://github.com/eth-clients/eth2-networks/blob/674f7a1d01d9c18345456eab76e3871b3df2126b/shared/medalla/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-medalla", test))]
    const MEDALLA_BOOTNODES: &'static [&'static str] = &[
        // > Proto's catdog v5.1:
        "enr:-Ku4QJmPsyq4lmDdFebMKXk7vdt8WsLWkArYT2K8eN057oFudm2tITrZJD9sq1x92-bRmXTyAJgb2FD4ior-KHIU3KcDh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDaNQiCAAAAA___________gmlkgnY0gmlwhBK4vdCJc2VjcDI1NmsxoQMWAsR84_ETgq4-14FV2x00ptmI-YU3tdkZV9CUgYPEnIN1ZHCCI1s",
        // > Proto's catdog v5.0:
        "enr:-Ku4QKYN_qSG6WnGMs33F4STy8canm2X7vLaz0MB6bA84YJ-GtT5CeUvkuYvMUX-mwuU3Ju14-2wZj7rjwx7eAthAL4Dh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDaNQiCAAAAA___________gmlkgnY0gmlwhBK4vdCJc2VjcDI1NmsxoQNYtv_PfWUWNRo99-21Y4dXl5Z-XGalHp-bJmDHod4x14N1ZHCCI1o",
        // > Prysm catdog v5.1:
        "enr:-Ku4QHWezvidY_m0dWEwERrNrqjEQWrlIx7b8K4EIxGgTrLmUxHCZPW5-t8PsS8nFxAJ8k8YacKP5zPRk5gbsTSsRTQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQMypP_ODwTuBq2v0oIdjPGCEyu9Hb_jHDbuIX_iNvBRGoN1ZHCCGWQ",
        "enr:-Ku4QOnVSyvzS3VbF87J8MubaRuTyfPi6B67XQg6-5eAV_uILAhn9geTTQmfqDIOcIeAxWHUUajQp6lYniAXPWncp6UBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQKekYKqUtwbaJKKCct_srE5-g7tBUm68mj_jpeSb7CCqYN1ZHCCC7g",
        // > Lighthouse v5.1:
        "enr:-LK4QCGFeQXjpQkgOfLHsbTjD65IOtSqV7Qo-Qdqv6SrL8lqFY7INPMMGP5uGKkVDcJkeXimSeNeypaZV3MHkcJgr9QCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhA37LMaJc2VjcDI1NmsxoQJ7k0mKtTd_kdEq251flOjD1HKpqgMmIETDoD-Msy_O-4N0Y3CCIyiDdWRwgiMo",
        "enr:-LK4QCpyWmMLYwC2umMJ_g0c9VY7YOFwZyaR80_tuQNTWOzJbaR82DDhVQYqmE_0gvN6Du5jwnxzIaaNRZQlVXzfIK0Dh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhCLR2xuJc2VjcDI1NmsxoQOYiWqrQtQksTEtS3qY6idxJE5wkm0t9wKqpzv2gCR21oN0Y3CCIyiDdWRwgiMo",
        // > Nimbus v5.1:
        "enr:-LK4QJB7elkI4tgh1WPymvSAAEZN8zwlMY-DBCItGTEFMCzBQa5XkwKEZQdlqx9iJffHo6yiMWCvCqHgpfJ_vsJrbDIBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKf8seJc2VjcDI1NmsxoQI_D7uq_K3EGNYF7jGeSuHSO5rVUpTGzcoCu4Dcipu-oYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QL373-Q7Gmte1jNtQhT0s9r3aoQakIoBSf9il9_dxo3CYqQP8FTSTQlEM45h6AiXOvfib94PI4Ea4GTbTpiYV9ABh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBK568yJc2VjcDI1NmsxoQKm0CSxPf5xe18RacrZbPjeyQAUXw86zwY6Txl-NJ4p4YN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QNeibtmTUb6vNtcQzP6qe0xoVjm7Er2GC2QJaxMkLTekLfBFfZwc3tNEEl3Ql2saoZeiDUEtg5NREccU9VEOh6oBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKfphGJc2VjcDI1NmsxoQJ_iPbLIoshdjyO9TCQCdpEN0zIbcr1cDe7Q_uNiK2wZYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QJCSSMh1qZAv1JenlTSvN1SIFng2716OaE9sZX-Sn1AFREJCtXoR6z64a4lleusKRjpYx8GK3pTyI1oZeAB_jwUBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKefnOJc2VjcDI1NmsxoQP9wdO3c7vqcbO61B8WFWMaR9khZhrIyq-WjIgtBOQJXIN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QGc1l6U2VMGbLCbkgxMBqQlYBcpMUDmee3wZuuzGQis4eMmlAmIr4LDGKJfNi6KK2ef95oCZQ49THfwlqTT2SqABh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKeCi6Jc2VjcDI1NmsxoQJ8FFbZanjspyvU3ln103-mfDFZeBJbjUWKz5AlxDh3TIN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QBOeYcroDfGCd6NrqsZ3SkpW5E_5LCS1023EhFU4M59PWsKgz8sIIOkK2AeylVF03wYOgiskc-0SodebPtREZBcBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKe5g-Jc2VjcDI1NmsxoQKcq5u0tc3v8pgm4LkFhslZhU9RPCnwAAdLurqv7ZI-TIN0Y3CCI4yDdWRwgiOM",
        // > Other
        "enr:-Ku4QLglCMIYAgHd51uFUqejD9DWGovHOseHQy7Od1SeZnHnQ3fSpE4_nbfVs8lsy8uF07ae7IgrOOUFU0NFvZp5D4wBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQJxCnE6v_x2ekgY_uoE1rtwzvGy40mq9eD66XfHPBWgIIN1ZHCCD6A",
        "enr:-Ku4QOdk3u7rXI5YvqwmEbApW_OLlRkq_yzmmhdlrJMcfviacLWwSm-tr1BOvamuRQqfc6lnMeec4E4ddOhd3KqCB98Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQKH3lxnglLqrA7L6sl5r7XFnckr3XCnlZMaBTYSdE8SHIN1ZHCCG1g",
        "enr:-Ku4QOVrqhlmsh9m2MGSnvVz8XPfjwHWBuOcgVQvWwBhN0-NI0XVhSerujBBwIeLpc-OES0C9iAzJhiCgRZ0xH13DgEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQLEq16KLm1vPjUKYGkHq296D60i7y209NYPUpwZPXDVgYN1ZHCCF3A",
        "enr:-LK4QC3FCb7-JTNRiWAezECk_QUJc9c2IkJA1-EAmqAA5wmdbPWsAeRpnMXKRJqOYG0TE99ycB1nOb9y26mjb_UoHS4Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhDMPYfCJc2VjcDI1NmsxoQOmDQryZJApMwIT-dQAbxjvxLbPzyKn9GFk5dqam4MDTYN0Y3CCIyiDdWRwgiMo",
        "enr:-LK4QLvxLzt346gAPkTxohygiJvjd97lGcFeE5yXgZKtsMfEOveLE_FO2slJoHNzNF7vhwfwjt4X2vqzwGiR9gcrmDMBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhDMPRgeJc2VjcDI1NmsxoQPjXTGx3HkaCG2neFxJmaTn5eCgbra3LY1twCeXPHChL4N0Y3CCIyiDdWRwgiMo",
        "enr:-Ku4QFVactU18ogiqPPasKs3jhUm5ISszUrUMK2c6SUPbGtANXVJ2wFapsKwVEVnVKxZ7Gsr9yEc4PYF-a14ahPa1q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAYrkzLAAAAAf__________gmlkgnY0gmlwhGQbAHyJc2VjcDI1NmsxoQILF-Ya2i5yowVkQtlnZLjG0kqC4qtwmSk8ha7tKLuME4N1ZHCCIyg",
        "enr:-KG4QFuKQ9eeXDTf8J4tBxFvs3QeMrr72mvS7qJgL9ieO6k9Rq5QuGqtGK4VlXMNHfe34Khhw427r7peSoIbGcN91fUDhGV0aDKQD8XYjwAAAAH__________4JpZIJ2NIJpcIQDhMExiXNlY3AyNTZrMaEDESplmV9c2k73v0DjxVXJ6__2bWyP-tK28_80lf7dUhqDdGNwgiMog3VkcIIjKA",
        "enr:-LK4QNifGuaUmm3zfqC8SHSjvJP9JICHj4DYz2aAMXfJssgaRBnTanMRRz_eoIIaz5gX31JHT28Ce_El8krAWnDmh2MCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhDQlA5CJc2VjcDI1NmsxoQOYiWqrQtQksTEtS3qY6idxJE5wkm0t9wKqpzv2gCR21oN0Y3CCIyiDdWRwgiMo",
        "enr:-LK4QBwf3yQV4A2H8piP7HI584BsXJYJqlH4v2kr25pEajFwTTsnF0-mC-nVLhbE_tV3Dfm1OSGHfY3TIJDhhk0vQwABh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhAN7IWiJc2VjcDI1NmsxoQN7SVjDI903lJ9olSB8a_Fp7zajPhh5FgEGD-lSOxonZYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QA5FEn7IcW83DyYmYgKEC5MNlfkXDyuH60EX4_GyapIbQJaPkkWaTgbU5mKIg8xd8Ek7Z7lRkPbh0U7E85DcLtoBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKcVIyJc2VjcDI1NmsxoQIKJAFKbLs9vR-4H4He8HvNxm03YIjORGmJIJoFJ3lPO4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QM2RJb5_1Wd1sMdLcdcRv7i397hCwXMEPyqRj1Wbn6HZGM0ioncwNnMDV163-0cNmTJLXuALbQoNufR6rX18LI8Bh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhDZd9S6Jc2VjcDI1NmsxoQPqwn1FZZKe3afNhwgqn3uQDNDOh5-Pr8qgVQMkSFahWYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QIolrZmrkGhK9_Q5qX44rFM6D6z7pXL_ilHRQ3rNunDqZQEvhDGART--MbLaMZxSZtOKpd9sP520edm3ZUVcwcIBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBLEvqqJc2VjcDI1NmsxoQKzNXbQu165tGZvK6sWqu44Fk9k_s93AmUzqIfbCyQyz4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QGvceQZPuO44DTEsb_HqvkiMl85Fva7qvg0s8pJ0lkU3J_pvDrrYsmOkp-e8Zgq8m5Ewimd4Xhe4ZBnLanY7d-ABh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhAN8wRKJc2VjcDI1NmsxoQJAGkv3ZK5DJLP8B07BkMSOp13LDYQEHloP65F4We9vSYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QFMUor7tPnQfx0CO8lBv1IicmvrlITSl7wMmf-SvBI9eGoOpSrn1TRG2WSxmEA7JKxkgqa_wZsCmqw_NUVEYf0EBh2F0dG5ldHOI__________-EZXRoMpDnp11aAAAAAf__________gmlkgnY0gmlwhBKdpCiJc2VjcDI1NmsxoQK7ayo4eVvgc_EzENnncZT5_KFhVEvC4jbu1w529m2j_YN0Y3CCI4yDdWRwgiOM",
    ];

    /// [Pyrmont bootnode ENRs](https://github.com/eth-clients/eth2-networks/blob/674f7a1d01d9c18345456eab76e3871b3df2126b/shared/pyrmont/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-pyrmont", test))]
    const PYRMONT_BOOTNODES: &'static [&'static str] = &[
        // > @protolambda bootnode 1
        "enr:-Ku4QOA5OGWObY8ep_x35NlGBEj7IuQULTjkgxC_0G1AszqGEA0Wn2RNlyLFx9zGTNB1gdFBA6ZDYxCgIza1uJUUOj4Dh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDVTPWXAAAgCf__________gmlkgnY0gmlwhDQPSjiJc2VjcDI1NmsxoQM6yTQB6XGWYJbI7NZFBjp4Yb9AYKQPBhVrfUclQUobb4N1ZHCCIyg",
        // > @protolambda bootnode 2
        "enr:-Ku4QOksdA2tabOGrfOOr6NynThMoio6Ggka2oDPqUuFeWCqcRM2alNb8778O_5bK95p3EFt0cngTUXm2H7o1jkSJ_8Dh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDVTPWXAAAgCf__________gmlkgnY0gmlwhDaa13aJc2VjcDI1NmsxoQKdNQJvnohpf0VO0ZYCAJxGjT0uwJoAHbAiBMujGjK0SoN1ZHCCIyg",
        // > lighthouse bootnode 1
        "enr:-LK4QDiPGwNomqUqNDaM3iHYvtdX7M5qngson6Qb2xGIg1LwC8-Nic0aQwO0rVbJt5xp32sRE3S1YqvVrWO7OgVNv0kBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBKNA4qJc2VjcDI1NmsxoQKbBS4ROQ_sldJm5tMgi36qm5I5exKJFb4C8dDVS_otAoN0Y3CCIyiDdWRwgiMo",
        // > lighthouse bootnode 2
        "enr:-LK4QKAezYUw_R4P1vkzfw9qMQQFJvRQy3QsUblWxIZ4FSduJ2Kueik-qY5KddcVTUsZiEO-oZq0LwbaSxdYf27EjckBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhCOmkIaJc2VjcDI1NmsxoQOQgTD4a8-rESfTdbCG0V6Yz1pUvze02jB2Py3vzGWhG4N0Y3CCIyiDdWRwgiMo",
        // > nimbus bootnodes
        "enr:-LK4QK6e16UnTLbi8mJuXHdUSNN8BUcUqhnhyy2bL2_JeX7iMfK9lRbtq8M4kMDGhFwyUQLkHxaDNxS0IPuGS53c1osBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhAN_0AGJc2VjcDI1NmsxoQOPQv1VILGXeB10y088SeuU6-w8Yh689Fv_uWjhtFqbLIN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QHy7BBDm_mxT0i-EBatHvHGfzNH4BcaAdNguNS8fuaxFDfHP0qVJ9f9A38Q_lMmRUK5PSVHEEoC1mwrExO51T2cBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBLGXiqJc2VjcDI1NmsxoQJV51WZn_NLj-0vHAmmZ6tWtzIdu-P_xVr7k9zMEkvaA4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QE8QIkEl2k67fj53vn6SgLwj07ElmWZJrIeEpZUfh91oe-PNAlIzeRwI47_wZTK1S2KretXF56XkZqP0v5VlBVUBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBLB_8yJc2VjcDI1NmsxoQOEowpACJVUFtcWKhpEk9HlEyY4AEcTB4fONkPEvpeYmIN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QJMF9O8D7hNcGP1Xxh5E09lxUwrzFwokYDxIxUjj_yOnDOWX5HjTDJ4TLZle3HVozC3vJuiZF7jImJMt79t8FuYBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBKeOTGJc2VjcDI1NmsxoQJLajuu1S9v-NREUDo5kzUY-ook9CqYLDiHf8z1nMSY1oN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QOTyWBISU1AysyKFt35m_epniDd54LEAsTS2x0OSo1FFTY2ZxETVm43VcZYkmYMQo2ECUAV-0RwAFZcC9_xjRQ4Bh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhAN9a7CJc2VjcDI1NmsxoQJCIUgdHgGuE_k9CVThmgiiXXYW1lfdCZbWHj4p_SAkY4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QHOOeQg3HjXSGoXGZPJYeBQ3o9beIGLU1Fxv2PIZX5NEeBLJPB9kpP5xNX_dJ23lsZ0RhBwAxXXTtziC9EMuZuMBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhCOc7_OJc2VjcDI1NmsxoQPMp2C3hjMNBt6Dr4npyfTG0__GpHtxYXrnho4lT2g2c4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QOMpgA7LUM-YUJqWWGX1t01wJkqDMjDJrhxyJHp7ZOCyWkJEYqkHOHYms_K6PI0Ky9Bw57R3ayk9LzE5E9v54WEBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBLApGOJc2VjcDI1NmsxoQNGyxAQW2ZUvt_n-MZByer467sfBWclC3pJtvnZDaLhZYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QL3Y2elAiia5WV18p_pu9t_7syTsZs-rWGD6_IHhiEvBUIzZtT88VMsI-rN8fNSukaHuq7qtDhZwRISdG9O4uQsBh2F0dG5ldHOI__________-EZXRoMpA7CIeVAAAgCf__________gmlkgnY0gmlwhBLGowKJc2VjcDI1NmsxoQK13jMsuO1LbguOsFZ0hxvRe7PT8V1W9qeUMs6fgiwuM4N0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QAtPY91umFgpKmvSEcsDdzXxB6Ss5pa55oqk-t58Uv9qF-B68jEjsN7B_SBGe4qCH1thKwokbS8-zC8Xy-NsED8Bh2F0dG5ldHOI__________-EZXRoMpDzGkhaAAAAAP__________gmlkgnY0gmlwhBKeqH2Jc2VjcDI1NmsxoQIRA0fHAr6eECjjIZZK-GB6dE0awWYtTrOMACfjq12M5oN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QLvxqICUmpMitpwHDwJNEUGj1ecsW_ZlGImx6SwfyFJICV2SO6lYcdxDKHAK0RzdWYo8dGm3tL__NpP_4Afy5psBh2F0dG5ldHOI__________-EZXRoMpDzGkhaAAAAAP__________gmlkgnY0gmlwhBLBEDqJc2VjcDI1NmsxoQJw2JPyabX2G_f9eAkbjhBDshIeUP-eZ-KoMGqFTdxUToN0Y3CCI4yDdWRwgiOM",
    ];

    /// [Goerli bootnode ENRs](https://github.com/eth-clients/eth2-networks/blob/674f7a1d01d9c18345456eab76e3871b3df2126b/shared/prater/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-goerli", test))]
    const GOERLI_BOOTNODES: &'static [&'static str] = &[
        // > q9f bootnode errai (lighthouse)
        // > /ip4/135.181.181.239/tcp/9000/p2p/16Uiu2HAmPitcpwsGZf1vGiu6hdwZHsVLyFzVZeNqaSmUaSyM7Xvj
        "enr:-LK4QH1xnjotgXwg25IDPjrqRGFnH1ScgNHA3dv1Z8xHCp4uP3N3Jjl_aYv_WIxQRdwZvSukzbwspXZ7JjpldyeVDzMCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpB53wQoAAAQIP__________gmlkgnY0gmlwhIe1te-Jc2VjcDI1NmsxoQOkcGXqbCJYbcClZ3z5f6NWhX_1YPFRYRRWQpJjwSHpVIN0Y3CCIyiDdWRwgiMo",
        // > q9f bootnode gudja (teku)
        // > /ip4/135.181.182.51/tcp/9000/p2p/16Uiu2HAmTttt9ZTmCmwmKiV3QR7iTAfnAckwzhswrNmWkthi6meB
        "enr:-KG4QCIzJZTY_fs_2vqWEatJL9RrtnPwDCv-jRBuO5FQ2qBrfJubWOWazri6s9HsyZdu-fRUfEzkebhf1nvO42_FVzwDhGV0aDKQed8EKAAAECD__________4JpZIJ2NIJpcISHtbYziXNlY3AyNTZrMaED4m9AqVs6F32rSCGsjtYcsyfQE2K8nDiGmocUY_iq-TSDdGNwgiMog3VkcIIjKA",
        // > Prysm bootnode #1
        "enr:-Ku4QFmUkNp0g9bsLX2PfVeIyT-9WO-PZlrqZBNtEyofOOfLMScDjaTzGxIb1Ns9Wo5Pm_8nlq-SZwcQfTH2cgO-s88Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDkvpOTAAAQIP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQLV_jMOIxKbjHFKgrkFvwDvpexo6Nd58TK5k7ss4Vt0IoN1ZHCCG1g",
        // > Lighthouse bootnode #1
        "enr:-LK4QLINdtobGquK7jukLDAKmsrH2ZuHM4k0TklY5jDTD4ZgfxR9weZmo5Jwu81hlKu3qPAvk24xHGBDjYs4o8f1gZ0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpB53wQoAAAQIP__________gmlkgnY0gmlwhDRN_P6Jc2VjcDI1NmsxoQJuNujTgsJUHUgVZML3pzrtgNtYg7rQ4K1tkWERgl0DdoN0Y3CCIyiDdWRwgiMo",
        // > Nimbus bootstrap nodes
        "enr:-LK4QMzPq4Q7w5R-rnGQDcI8BYky6oPVBGQTbS1JJLVtNi_8PzBLV7Bdzsoame9nJK5bcJYpGHn4SkaDN2CM6tR5G_4Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpB53wQoAAAQIP__________gmlkgnY0gmlwhAN4yvyJc2VjcDI1NmsxoQKa8Qnp_P2clLIP6VqLKOp_INvEjLszalEnW0LoBZo4YYN0Y3CCI4yDdWRwgiOM",
        "enr:-LK4QLM_pPHa78R8xlcU_s40Y3XhFjlb3kPddW9lRlY67N5qeFE2Wo7RgzDgRs2KLCXODnacVHMFw1SfpsW3R474RZEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpB53wQoAAAQIP__________gmlkgnY0gmlwhANBY-yJc2VjcDI1NmsxoQNsZkFXgKbTzuxF7uwxlGauTGJelE6HD269CcFlZ_R7A4N0Y3CCI4yDdWRwgiOM",
        // > Teku bootnode
        "enr:-KK4QH0RsNJmIG0EX9LSnVxMvg-CAOr3ZFF92hunU63uE7wcYBjG1cFbUTvEa5G_4nDJkRhUq9q2ck9xY-VX1RtBsruBtIRldGgykIL0pysBABAg__________-CaWSCdjSCaXCEEnXQ0YlzZWNwMjU2azGhA1grTzOdMgBvjNrk-vqWtTZsYQIi0QawrhoZrsn5Hd56g3RjcIIjKIN1ZHCCIyg",
    ];

    /// [Kintsugi bootnode ENRs](https://github.com/eth-clients/merge-testnets/blob/302fe27afdc7a9d15b1766a0c0a9d64319140255/kintsugi/bootstrap_nodes.txt)
    ///
    /// `README.md` has one extra bootnode that was removed from `boot_enr.yaml`.
    #[cfg(any(feature = "network-kintsugi", test))]
    const KINTSUGI_BOOTNODES: &'static [&'static str] = &[
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-Ly4QOMHhGw2RIq9sHGHdSrhpjBJ421HplSN80sVyaNJkdUDSACc2_CXb1B-PJs9TR5yuV5xItUR4fcsaZZNHKCSC1QSh2F0dG5ldHOI__________-EZXRoMpDucelzYgAAcf__________gmlkgnY0gmlwhKXouc-Jc2VjcDI1NmsxoQO_Mk0rN4Q4vheqeFkz0bA9uWO8Cq51rNAxfq3rhNRKZIhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
        "enr:-L24QNzlHJhdNf8OXLMdc5qrCI9iwEoTOJHz66YxtVStBVmXEwOFzWqFitxNfc6_ckUhhBZKWT6J-BO5JmikXu3fcOWBk4dhdHRuZXRziP__________hGV0aDKQ7nHpc2IAAHH__________4JpZIJ2NIJpcIRA4QTfiXNlY3AyNTZrMaED4DY2_MH1Q66-9YRxcxhSO5hqaUd-IGqOsMXJfcCfnW2Ic3luY25ldHMPg3RjcIIjKIN1ZHCCIyg",
        "enr:-Ly4QCz_0NonV_RhGRbI8lezNtdzkK9gEvfQsvQdCiuZcqYGTuoCrRdhpKINp90_nClvi7of2Sq0AcNMk1-BMO91rqMOh2F0dG5ldHOI__________-EZXRoMpDucelzYgAAcf__________gmlkgnY0gmlwhKXosXmJc2VjcDI1NmsxoQJuQwF3fUjF432CpNvXqv5R6c4ZKr7jFX2Bzjdy9hW79IhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
        "enr:-L24QJu98clS2Xl1L80iDeSCr4D_VDFl7S-63fmuAcxTy3RwThEy1JrHy2dkCq_7RYZz_y4D04o8C4iOIHd0Bb86PQCBgYdhdHRuZXRziO309Lg2pfflhGV0aDKQ7nHpc2IAAHH__________4JpZIJ2NIJpcIShI0tOiXNlY3AyNTZrMaEDH7tt6r2IO9tq5vSfHJtdi1wTBb37n29yVaQ2iAZSE3qIc3luY25ldHMPg3RjcIIjKIN1ZHCCIyg",
    ];

    /// [Kiln bootnode ENRs](https://github.com/eth-clients/merge-testnets/blob/302fe27afdc7a9d15b1766a0c0a9d64319140255/kiln/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-kiln", test))]
    const KILN_BOOTNODES: &'static [&'static str] = &[
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-KG4QFkPJUFWuONp5grM94OJvNht9wX6N36sA4wqucm6Z02ECWBQRmh6AzndaLVGYBHWre67mjK-E0uKt2CIbWrsZ_8DhGV0aDKQc6pfXHAAAHAyAAAAAAAAAIJpZIJ2NIJpcISl6LTmiXNlY3AyNTZrMaEDHlSNOgYrNWP8_l_WXqDMRvjv6gUAvHKizfqDDVc8feaDdGNwgiMog3VkcIIjKA",
        "enr:-MK4QI-wkVW1PxL4ksUM4H_hMgTTwxKMzvvDMfoiwPBuRxcsGkrGPLo4Kho3Ri1DEtJG4B6pjXddbzA9iF2gVctxv42GAX9v5WG5h2F0dG5ldHOIAAAAAAAAAACEZXRoMpBzql9ccAAAcDIAAAAAAAAAgmlkgnY0gmlwhKRcjMiJc2VjcDI1NmsxoQK1fc46pmVHKq8HNYLkSVaUv4uK2UBsGgjjGWU6AAhAY4hzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    ];

    /// [Ropsten bootnode ENRs](https://github.com/eth-clients/merge-testnets/blob/302fe27afdc7a9d15b1766a0c0a9d64319140255/ropsten-beacon-chain/README.md)
    #[cfg(any(feature = "network-ropsten", test))]
    const ROPSTEN_BOOTNODES: &'static [&'static str] = &[
        // > EF bootnode
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-L64QLKGahA2AQwFUrX1rpad2zfSgtSwdFUSAH2vLwYkFaGIFtaCKwllLVeRyaxm_EiJA_AnIut11VBWssanktwEzmOCAQyHYXR0bmV0c4j__________4RldGgykDz6O6yAAABx__________-CaWSCdjSCaXCEojetBIlzZWNwMjU2azGhAmIKKR-unrW_VMUSW9ctYQVt4rYRD7HmQ48xkM-yNyxKiHN5bmNuZXRzBoN0Y3CCIyiDdWRwgiMo",
        "enr:-Ly4QBKxH0EE-Z1VHY7GbxgV6axbnD0jJoeHsj0tOY7DeOyqW1GhIrgEyxb6Rl_rS10qrgrBtJOI8Yt3bd7rXHk3GBlsh2F0dG5ldHOI__________-EZXRoMpA8-jusgAAAcf__________gmlkgnY0gmlwhKfr5v6Jc2VjcDI1NmsxoQPmax4TV2mAzlHJV1J0l-6tQkHui-iIJ7mcCiyE9YREMohzeW5jbmV0cwyDdGNwgiMog3VkcIIjKA",
        "enr:-Ly4QKEbHPy_jbA3xy_ZR04LVyJ8x2vGoVSUZ2QvoLHTHiCoeWraxyWwl3MhRupM0aXbr8U_OBJ2GkqZAxbY1I5boJtRh2F0dG5ldHOI__________-EZXRoMpA8-jusgAAAcf__________gmlkgnY0gmlwhAWhjUqJc2VjcDI1NmsxoQLTpctSHKHGN7nGTQmCP4-PSTtSYcppPqGTkvCbR-iUAIhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
        "enr:-Ly4QBPqYWxS4x6UuU2IbDFGRYpMj-z1-rtoRFXGw6uJ0fQ0Rix0Vtak2dSl0SO0w50WKTSmFubSpHkxLmeHJ7kZ-S1Rh2F0dG5ldHOI__________-EZXRoMpA8-jusgAAAcf__________gmlkgnY0gmlwhAWhhAmJc2VjcDI1NmsxoQPpPhUwcdObdY1ERHpiR2X7vaAZ05xwHs1uLEIUjea044hzeW5jbmV0cwmDdGNwgiMog3VkcIIjKA",
        "enr:-L64QOfVzGCvyI73fW6IFzugYZr0QfYItn0j19P8zgbmgFdJKIdFLUp7lynEwy0U9YgFhKF4NF4PumailtLAmUv4bM2CApmHYXR0bmV0c4j__________4RldGgykDz6O6yAAABx__________-CaWSCdjSCaXCEh7WWsIlzZWNwMjU2azGhAsMdsKC6SYYlIN7huLAhhxxRzOJOka7gpfnFZ2Auq0kiiHN5bmNuZXRzBoN0Y3CCIyiDdWRwgiMo",
        "enr:-L64QNCPH53Je5MJ_TbKHnPSqKO1XZtywJK4gF4UA3UcQyHZEJKpcPHbXYnibrDUB7XEbZ1NW2INUK9uSD2ecOVVXfmCARCHYXR0bmV0c4j__________4RldGgykDz6O6yAAABx__________-CaWSCdjSCaXCEQWz6UYlzZWNwMjU2azGhAovELkeemN_zzm-wEyQJo8p0DgiM4o32zSDQkiR1LOIIiHN5bmNuZXRzA4N0Y3CCIyiDdWRwgiMo",
        "enr:-L64QESLzEbBz8I38oLg1PX1ATTGZUQ5KUadgy4UAZqSsutLdW4rSASTCFKL0ssqmq0lUXEF7aP-4gvuDB9IvVb42syCAx6HYXR0bmV0c4j__________4RldGgykDz6O6yAAABx__________-CaWSCdjSCaXCEw8ndRIlzZWNwMjU2azGhAirZcWMVxDPb5T4exQOfGRxIHICCcAxSpi1_mCaehUgyiHN5bmNuZXRzDIN0Y3CCIyiDdWRwgiMo",
        "enr:-L24QN8Y-8WTMuwF8ePM2wOjzlMdLOYwl3QJmXs1KILv6ZZwVovYC822cb-nh1R2U3Hi6AiHS5SsINNrHzLQVzFrsduBg4dhdHRuZXRziP__________hGV0aDKQPPo7rIAAAHH__________4JpZIJ2NIJpcITDyd1CiXNlY3AyNTZrMaECroNSTYv0Gy272DBfn-in38LLREpMwzOP18LoLrYJ4jeIc3luY25ldHMJg3RjcIIjKIN1ZHCCIyg",
        // > Teku bootnode
        "enr:-KG4QMJSJ7DHk6v2p-W8zQ3Xv7FfssZ_1E3p2eY6kN13staMObUonAurqyWhODoeY6edXtV8e9eL9RnhgZ9va2SMDRQMhGV0aDKQS-iVMYAAAHD0AQAAAAAAAIJpZIJ2NIJpcIQDhAAhiXNlY3AyNTZrMaEDXBVUZhhmdy1MYor1eGdRJ4vHYghFKDgjyHgt6sJ-IlCDdGNwgiMog3VkcIIjKA",
    ];

    /// [Sepolia bootnode ENRs](https://github.com/eth-clients/merge-testnets/blob/302fe27afdc7a9d15b1766a0c0a9d64319140255/sepolia/README.md)
    #[cfg(any(feature = "network-sepolia", test))]
    const SEPOLIA_BOOTNODES: &'static [&'static str] = &[
        // > EF bootnode
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-KG4QE5OIg5ThTjkzrlVF32WT_-XT14WeJtIz2zoTqLLjQhYAmJlnk4ItSoH41_2x0RX0wTFIe5GgjRzU2u7Q1fN4vADhGV0aDKQqP7o7pAAAHAyAAAAAAAAAIJpZIJ2NIJpcISlFsStiXNlY3AyNTZrMaEC-Rrd_bBZwhKpXzFCrStKp1q_HmGOewxY3KwM8ofAj_ODdGNwgiMog3VkcIIjKA",
        // > Teku bootnode
        "enr:-Ly4QFoZTWR8ulxGVsWydTNGdwEESueIdj-wB6UmmjUcm-AOPxnQi7wprzwcdo7-1jBW_JxELlUKJdJES8TDsbl1EdNlh2F0dG5ldHOI__78_v2bsV-EZXRoMpA2-lATkAAAcf__________gmlkgnY0gmlwhBLYJjGJc2VjcDI1NmsxoQI0gujXac9rMAb48NtMqtSTyHIeNYlpjkbYpWJw46PmYYhzeW5jbmV0cw-DdGNwgiMog3VkcIIjKA",
        // > Another bootnode
        "enr:-L64QC9Hhov4DhQ7mRukTOz4_jHm4DHlGL726NWH4ojH1wFgEwSin_6H95Gs6nW2fktTWbPachHJ6rUFu0iJNgA0SB2CARqHYXR0bmV0c4j__________4RldGgykDb6UBOQAABx__________-CaWSCdjSCaXCEA-2vzolzZWNwMjU2azGhA17lsUg60R776rauYMdrAz383UUgESoaHEzMkvm4K6k6iHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",

    ];

    /// [Withdrawal devnet 4 ENRs](https://github.com/ethpandaops/withdrawals-testnet/blob/a87272d32cc69766629f4a10b1d5183637747914/withdrawal-devnet-4/custom_config_data/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-withdrawals", test))]
    const WITHDRAWALS_BOOTNODES: &'static [&'static str] = &[
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-Ly4QPqATloC2-lrv-P26WQ6kmFQj3v1-Ss-N0Z12piMmdXiQsgPy3Wihr_pPJKpMK-dJifbzIR0LYzVTqhWqZjCByABh2F0dG5ldHOIAAAAAAAAAACEZXRoMpDN1qioQAAAQRQAAAAAAAAAgmlkgnY0gmlwhJK-FaaJc2VjcDI1NmsxoQP4H8gVZIpu_490Zdb1YX2R9wqYLkMztg0zHM8j3295CohzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
    ];

    /// [Holesky bootnode ENRs](https://github.com/eth-clients/holesky/blob/f1ad227a2511ea26f5d043fad15d9431fd681941/custom_config_data/bootstrap_nodes.txt)
    #[cfg(any(feature = "network-holesky", test))]
    const HOLESKY_BOOTNODES: &'static [&'static str] = &[
        // EF
        "enr:-Ku4QFo-9q73SspYI8cac_4kTX7yF800VXqJW4Lj3HkIkb5CMqFLxciNHePmMt4XdJzHvhrCC5ADI4D_GkAsxGJRLnQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAhnTT-AQFwAP__________gmlkgnY0gmlwhLKAiOmJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyk",
        "enr:-Ku4QPG7F72mbKx3gEQEx07wpYYusGDh-ni6SNkLvOS-hhN-BxIggN7tKlmalb0L5JPoAfqD-akTZ-gX06hFeBEz4WoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAhnTT-AQFwAP__________gmlkgnY0gmlwhJK-DYCJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyk",
        "enr:-LK4QPxe-mDiSOtEB_Y82ozvxn9aQM07Ui8A-vQHNgYGMMthfsfOabaaTHhhJHFCBQQVRjBww_A5bM1rf8MlkJU_l68Eh2F0dG5ldHOIAADAAAAAAACEZXRoMpBpt9l0BAFwAAABAAAAAAAAgmlkgnY0gmlwhLKAiOmJc2VjcDI1NmsxoQJu6T9pclPObAzEVQ53DpVQqjadmVxdTLL-J3h9NFoCeIN0Y3CCIyiDdWRwgiMo",
        "enr:-Ly4QGbOw4xNel5EhmDsJJ-QhC9XycWtsetnWoZ0uRy381GHdHsNHJiCwDTOkb3S1Ade0SFQkWJX_pgb3g8Jfh93rvMBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpBpt9l0BAFwAAABAAAAAAAAgmlkgnY0gmlwhJK-DYCJc2VjcDI1NmsxoQOxKv9sv3zKF8GDewgFGGHKP5HCZZpPpTrwl9eXKAWGxIhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
        // TEKU
        "enr:-LS4QG0uV4qvcpJ-HFDJRGBmnlD3TJo7yc4jwK8iP7iKaTlfQ5kZvIDspLMJhk7j9KapuL9yyHaZmwTEZqr10k9XumyCEcmHYXR0bmV0c4gAAAAABgAAAIRldGgykGm32XQEAXAAAAEAAAAAAACCaWSCdjSCaXCErK4j-YlzZWNwMjU2azGhAgfWRBEJlb7gAhXIB5ePmjj2b8io0UpEenq1Kl9cxStJg3RjcIIjKIN1ZHCCIyg",
        // Sigma Prime
        "enr:-Le4QLoE1wFHSlGcm48a9ZESb_MRLqPPu6G0vHqu4MaUcQNDHS69tsy-zkN0K6pglyzX8m24mkb-LtBcbjAYdP1uxm4BhGV0aDKQabfZdAQBcAAAAQAAAAAAAIJpZIJ2NIJpcIQ5gR6Wg2lwNpAgAUHQBwEQAAAAAAAAADR-iXNlY3AyNTZrMaEDPMSNdcL92uNIyCsS177Z6KTXlbZakQqxv3aQcWawNXeDdWRwgiMohHVkcDaCI4I",
    ];

    #[must_use]
    pub fn chain_config(self) -> ChainConfig {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => ChainConfig::mainnet(),
            #[cfg(any(feature = "network-medalla", test))]
            Self::Medalla => ChainConfig::medalla(),
            #[cfg(any(feature = "network-pyrmont", test))]
            Self::Pyrmont => ChainConfig::pyrmont(),
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => ChainConfig::goerli(),
            #[cfg(any(feature = "network-kintsugi", test))]
            Self::Kintsugi => ChainConfig::kintsugi(),
            #[cfg(any(feature = "network-kiln", test))]
            Self::Kiln => ChainConfig::kiln(),
            #[cfg(any(feature = "network-ropsten", test))]
            Self::Ropsten => ChainConfig::ropsten(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => ChainConfig::sepolia(),
            #[cfg(any(feature = "network-withdrawals", test))]
            Self::Withdrawals => ChainConfig::withdrawal_devnet_4(),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => ChainConfig::holesky(),
        }
    }

    pub async fn genesis_provider<P: Preset>(
        self,
        client: &Client,
        store_directory: impl AsRef<Path> + Send,
        checkpoint_sync_url: Option<Url>,
    ) -> Result<GenesisProvider<P>> {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => predefined_chains::mainnet::<P>(),
            #[cfg(any(feature = "network-medalla", test))]
            Self::Medalla => predefined_chains::medalla::<P>(),
            #[cfg(any(feature = "network-pyrmont", test))]
            Self::Pyrmont => predefined_chains::pyrmont::<P>(),
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => predefined_chains::goerli::<P>(),
            #[cfg(any(feature = "network-kintsugi", test))]
            Self::Kintsugi => predefined_chains::kintsugi::<P>(),
            #[cfg(any(feature = "network-kiln", test))]
            Self::Kiln => predefined_chains::kiln::<P>(),
            #[cfg(any(feature = "network-ropsten", test))]
            Self::Ropsten => predefined_chains::ropsten::<P>(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => predefined_chains::sepolia::<P>(),
            #[cfg(any(feature = "network-withdrawals", test))]
            Self::Withdrawals => predefined_chains::withdrawal_devnet_4::<P>(),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => load_holesky_genesis_state(
                &self.chain_config(),
                client,
                store_directory,
                checkpoint_sync_url,
            )
            .await
            .map(GenesisProvider::Custom)
            .context("failed to load Holesky genesis state")?,
        }
        .pipe(Ok)
    }

    #[must_use]
    pub fn genesis_deposit_tree(self) -> DepositTree {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => Self::mainnet_genesis_deposit_tree(),
            #[cfg(any(feature = "network-medalla", test))]
            Self::Medalla => Self::medalla_genesis_deposit_tree(),
            #[cfg(any(feature = "network-pyrmont", test))]
            Self::Pyrmont => Self::pyrmont_genesis_deposit_tree(),
            // TODO(Grandine Team): The remaining `DepositTree`s are incorrect. `validator` will be
            //                      unable to construct valid deposit proofs when using them.
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => DepositTree {
                last_added_block_number: 4_367_322,
                ..DepositTree::default()
            },
            #[cfg(any(feature = "network-kintsugi", test))]
            Self::Kintsugi => DepositTree::default(),
            #[cfg(any(feature = "network-kiln", test))]
            Self::Kiln => DepositTree::default(),
            #[cfg(any(feature = "network-ropsten", test))]
            Self::Ropsten => DepositTree {
                last_added_block_number: 12_269_949,
                ..DepositTree::default()
            },
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => DepositTree {
                last_added_block_number: 1_273_020,
                ..DepositTree::default()
            },
            #[cfg(any(feature = "network-withdrawals", test))]
            Self::Withdrawals => DepositTree::default(),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => DepositTree::default(),
        }
    }

    #[cfg(any(feature = "network-mainnet", test))]
    fn mainnet_genesis_deposit_tree() -> DepositTree {
        DepositTree {
            #[rustfmt::skip]
            merkle_tree: [
                H256(hex!("ca3bfce2c304c4f52e0c83f96daf8c98a05f80281b62cf08f6be9c1bc10c0adb")),
                H256(hex!("abcf2f74605a9eb36cf243bb5009259a3717d44df3caf02acc53ab49cfd2eeb6")),
                H256(hex!("d4079d31e57638b3a6928ff3940d0d06545ae164278597bb8d46053084c335ea")),
                H256(hex!("f9585ef52fc5eaf1f11718df7988d3f414d8b0be2e56e15d7ade9f5ee4cc7ee4")),
                H256(hex!("a4c96f16c3a300034788ba8bf79c3125a697488006a4a4288c38fdc4e9891891")),
                H256(hex!("cae036d14b83ff1523749d4fabf5c91e8d455dce2f14eae3408dce22f901efc7")),
                H256(hex!("858ccad1a32af9e9796d3026ba18925103cad44cba4bdc1f3d3c23be125bba18")),
                H256(hex!("11f1e08405d5d180444147397ea0d4aebf12edff5cebc52cb05983c8d4bd2d4a")),
                H256(hex!("93d66676459ab2c5ca9d553a5c5599cc6992ed90edc939c51cc99d1820b56919")),
                H256(hex!("14bfcab6eb8016c5177e9e8f006e7893ea46b232b91b1f923b05273a927cd6d0")),
                H256(hex!("aa14720bc149ce68f20809d6fe55816acf09e72c14b54637dea24eb961558a7a")),
                H256(hex!("c726d03ced287a817fa8fea71c90bd89955b093d7c5908305177efa828945719")),
                H256(hex!("0435298b2d5b2b67543e4dceaf2c8b7fdbdac12836a70ed910c34abcd10b3ddf")),
                H256(hex!("53f640c85e35fef7e7ba4ab8c561fe9f1d763a32c65a1fbad57566bda1352362")),
                H256(hex!("57aa502116cb72c9347d10dca1b64a342b41a829cc7ba95e71499f57be2be3cd")),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
            ].into(),
            deposit_count: 21073,
            last_added_block_number: 11_320_899,
        }
    }

    #[cfg(any(feature = "network-medalla", test))]
    fn medalla_genesis_deposit_tree() -> DepositTree {
        DepositTree {
            #[rustfmt::skip]
            merkle_tree: [
                H256(hex!("1a681904fc274c629c0fe89054b8e15db5717e54bad61bed3ef2b0cced8772f3")),
                H256(hex!("cce101ecdf02448d270eafdff24fec87ae74c0ced890bfe2a36666c34bac936c")),
                H256(hex!("1a649df2fbfa1a77bcfbbe4cf2a5a58a4bd98ab3bca5bdd48a489d521955b4b1")),
                H256(hex!("01f62bbdeec3b593e949b32fef76e187fa99f0b8c57c09503cb974ca93e8f428")),
                H256(hex!("375d048b5d6e1010a1e72a8d146b8d8897c313554ba89e4a751a27cd44cb2ae4")),
                H256(hex!("31dbcb8e191fac2615e3620e0b2f55f206d099c41c7c2fe5cd7969e0507cc358")),
                H256(hex!("07f0daefe3350fad856e727f5e6604385da63be08e180235b7cee00f1bdd94a3")),
                H256(hex!("8a49d3a47f7bcfbb5390d7062ca297fb48bd3156ab152fe1027e852bd195f435")),
                H256(hex!("78ec812edc7c93acf992546754ff8e0a8418b426ed549a3008c1970d1d849e57")),
                H256(hex!("ded2b014cf6a72453b3018efb1724511c0364da5f8e01d59cba364e2f01ede87")),
                H256(hex!("3efcfb554a62634001d3d2a467db161163025eb4aabdee26cf64e12c862428f5")),
                H256(hex!("34de0ac00b9660815585d2046edac18073bb02c409273b01dfe8f0c39c298c5a")),
                H256(hex!("862e92a7dba09d0805632befc2391eff459861da0b4968f25e57e07a7434b7cd")),
                H256(hex!("31f390dfe6860812b5bece8354bbc6b7135a3793035d915c73e482c88f1be26e")),
                H256(hex!("e85c2ce1806ef2ecd85426aad3b38132a2f372bfc01641d3b3cee8d5a47d1a87")),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
            ].into(),
            deposit_count: 20673,
            last_added_block_number: 3_154_446,
        }
    }

    #[cfg(any(feature = "network-pyrmont", test))]
    fn pyrmont_genesis_deposit_tree() -> DepositTree {
        DepositTree {
            #[rustfmt::skip]
            merkle_tree: [
                H256(hex!("91cc8b48d9794bb9c598aa704f479985b79e5b5cbf928b0e5cbe704eb57282c9")),
                H256(hex!("da120fa74040c92e5a058b6776d9936a029c26e36ade928f202ea9583e88bad0")),
                H256(hex!("0ffe602e68867c9de7891ea4679e596647fde267073e0c1425805a8e06a38aa6")),
                H256(hex!("f7c00ab3077d28f7dab86ccf3f3de364839f3a3f1ab79fca347ee5f57c743c3e")),
                H256(hex!("f4fadb14b4f16ac5ff950e600d3d0c36ca08fc7ab4431275780b48b501b7e5d1")),
                H256(hex!("e713637b69e54e90a9c09190d21e22347eddd47004c76f232af56b7d20ef81cd")),
                H256(hex!("48ce52ea8e0b266bc9d793982fc1be9b072e902ede217091704a36bcaf22f4b2")),
                H256(hex!("818ea8d326b36d580331f1f05c3bea38e22bce688fac21b4b051efed69b92ce2")),
                H256(hex!("708c19f94a99f836d1b761f7ff65677ca2fb7a3149255e542f5cbb88c562d820")),
                H256(hex!("38958df062b220f8ddbd96ededba71f70233e0c1fba79328b7070ee04fc0e094")),
                H256(hex!("e850a4d7daad1bbdc976de4c7ba916c1dc01c2cafc44f96897cefe4d9a007d50")),
                H256(hex!("ef5164fb2ec1e2d0959f4df95a51f4238bf01eb0c3002dfa9da9585acbe932b3")),
                H256(hex!("0358b9aa39ebf9f2f378f08f7e93ff858635e6a21a098b74e7d011a7e13df3d6")),
                H256(hex!("5e99269d454f3423f6d5dc877bf0f95fc1c0f9f3cca9da232d7b76bbdbffc4b5")),
                H256(hex!("b3a1be7c7b6b5d23b3d4ae89f64eda351e565e425a21dfd531a145b61138caae")),
                H256(hex!("80239ececbfcf48fe96f5861b1e3b78d7ebf71dbff553718a3302402e5c251df")),
                H256(hex!("8f59af003a6d829c8c867d13b9360b7363bf770288269aa7d0accfaea3574a8d")),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
                H256::zero(),
            ].into(),
            deposit_count: 100_010,
            last_added_block_number: 3_746_432,
        }
    }

    #[must_use]
    pub fn network_config(self) -> NetworkConfig {
        let mut config = runtime::default_network_config();
        config.boot_nodes_enr = self.bootnodes();
        config
    }

    fn bootnodes(self) -> Vec<Enr> {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => Self::MAINNET_BOOTNODES,
            #[cfg(any(feature = "network-medalla", test))]
            Self::Medalla => Self::MEDALLA_BOOTNODES,
            #[cfg(any(feature = "network-pyrmont", test))]
            Self::Pyrmont => Self::PYRMONT_BOOTNODES,
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => Self::GOERLI_BOOTNODES,
            #[cfg(any(feature = "network-kintsugi", test))]
            Self::Kintsugi => Self::KINTSUGI_BOOTNODES,
            #[cfg(any(feature = "network-kiln", test))]
            Self::Kiln => Self::KILN_BOOTNODES,
            #[cfg(any(feature = "network-ropsten", test))]
            Self::Ropsten => Self::ROPSTEN_BOOTNODES,
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => Self::SEPOLIA_BOOTNODES,
            #[cfg(any(feature = "network-withdrawals", test))]
            Self::Withdrawals => Self::WITHDRAWALS_BOOTNODES,
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => Self::HOLESKY_BOOTNODES,
            #[allow(unreachable_patterns)]
            _ => &[],
        }
        .iter()
        .copied()
        .map(str::parse)
        .map(|result| result.expect("bootnode ENR should be valid"))
        .collect()
    }
}

async fn load_holesky_genesis_state<P: Preset>(
    config: &ChainConfig,
    client: &Client,
    store_directory: impl AsRef<Path> + Send,
    checkpoint_sync_url: Option<Url>,
) -> Result<Arc<BeaconState<P>>> {
    let genesis_state_path = store_directory.as_ref().join("genesis_state.ssz");

    let ssz_bytes = match fs_err::tokio::read(genesis_state_path.as_path()).await {
        Ok(bytes) => bytes.into(),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if let Some(url) = checkpoint_sync_url {
                let finalized_checkpoint =
                    checkpoint_sync::load_finalized_from_remote(config, client, &url).await?;

                return Ok(finalized_checkpoint.state);
            }

            let bytes = client
                .get("https://github.com/eth-clients/holesky/raw/main/custom_config_data/genesis.ssz")
                .timeout(Duration::from_secs(600))
                .send()
                .await?
                .bytes()
                .await?;

            fs_err::tokio::write(genesis_state_path, &bytes).await?;

            bytes
        }
        Err(error) => bail!(error),
    };

    Arc::from_ssz(&ChainConfig::holesky(), ssz_bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use types::{
        preset::{Mainnet, Medalla},
        traits::BeaconState as _,
    };

    use super::*;

    #[test_case(PredefinedNetwork::Mainnet)]
    #[test_case(PredefinedNetwork::Pyrmont)]
    #[test_case(PredefinedNetwork::Goerli)]
    #[test_case(PredefinedNetwork::Kintsugi)]
    #[test_case(PredefinedNetwork::Kiln)]
    #[test_case(PredefinedNetwork::Ropsten)]
    #[test_case(PredefinedNetwork::Sepolia)]
    #[test_case(PredefinedNetwork::Withdrawals)]
    fn genesis_state_and_deposit_tree_valid(predefined_network: PredefinedNetwork) {
        assert_deposit_tree_valid::<Mainnet>(predefined_network)
    }

    #[test]
    fn medalla_genesis_state_and_deposit_tree_valid() {
        assert_deposit_tree_valid::<Medalla>(PredefinedNetwork::Medalla)
    }

    fn assert_deposit_tree_valid<P: Preset>(predefined_network: PredefinedNetwork) {
        let genesis_provider = predefined_network
            .genesis_provider::<P>(&Client::new(), "", None)
            .pipe(futures::executor::block_on)
            .expect("this test should not load files or access the network");

        let state = genesis_provider.state();
        let deposit_tree = predefined_network.genesis_deposit_tree();

        assert_eq!(state.eth1_data().deposit_count, deposit_tree.deposit_count);
        assert_eq!(state.eth1_deposit_index(), deposit_tree.deposit_count);
    }
}
