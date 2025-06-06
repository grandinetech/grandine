use core::time::Duration;
use std::{io::ErrorKind, path::Path, sync::Arc};

use anyhow::{bail, Context as _, Result};
use deposit_tree::DepositTree;
use genesis::AnchorCheckpointProvider;
use log::info;
use p2p::{Enr, NetworkConfig};
use reqwest::Client;
use ssz::SszRead as _;
use strum::Display;
use tap::Pipe as _;
use types::{
    config::Config as ChainConfig,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    preset::Preset,
    redacting_url::RedactingUrl,
    traits::BeaconState as _,
};

#[cfg(any(feature = "network-mainnet", test))]
use ::{hex_literal::hex, types::phase0::primitives::H256};

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum PredefinedNetwork {
    #[cfg(any(feature = "network-mainnet", test))]
    Mainnet,
    #[cfg(any(feature = "network-sepolia", test))]
    Sepolia,
    #[cfg(any(feature = "network-holesky", test))]
    Holesky,
    #[cfg(any(feature = "network-hoodi", test))]
    Hoodi,
}

impl PredefinedNetwork {
    /// [Mainnet bootnode ENRs](https://github.com/eth-clients/mainnet/blob/6c9a688d289697d44614c7dfaf9154cc6565cb06/metadata/bootstrap_nodes.yaml)
    #[cfg(any(feature = "network-mainnet", test))]
    pub const MAINNET_BOOTNODES: &'static [&'static str] = &[
        // > Teku team's bootnodes
        "enr:-Iu4QLm7bZGdAt9NSeJG0cEnJohWcQTQaI9wFLu3Q7eHIDfrI4cwtzvEW3F3VbG9XdFXlrHyFGeXPn9snTCQJ9bnMRABgmlkgnY0gmlwhAOTJQCJc2VjcDI1NmsxoQIZdZD6tDYpkpEfVo5bgiU8MGRjhcOmHGD2nErK0UKRrIN0Y3CCIyiDdWRwgiMo",
        "enr:-Iu4QEDJ4Wa_UQNbK8Ay1hFEkXvd8psolVK6OhfTL9irqz3nbXxxWyKwEplPfkju4zduVQj6mMhUCm9R2Lc4YM5jPcIBgmlkgnY0gmlwhANrfESJc2VjcDI1NmsxoQJCYz2-nsqFpeEj6eov9HSi9QssIVIVNr0I89J1vXM9foN0Y3CCIyiDdWRwgiMo",

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

        // > Lodestar team's bootnodes
        "enr:-IS4QPi-onjNsT5xAIAenhCGTDl4z-4UOR25Uq-3TmG4V3kwB9ljLTb_Kp1wdjHNj-H8VVLRBSSWVZo3GUe3z6k0E-IBgmlkgnY0gmlwhKB3_qGJc2VjcDI1NmsxoQMvAfgB4cJXvvXeM6WbCG86CstbSxbQBSGx31FAwVtOTYN1ZHCCIyg",
        "enr:-KG4QCb8NC3gEM3I0okStV5BPX7Bg6ZXTYCzzbYyEXUPGcZtHmvQtiJH4C4F2jG7azTcb9pN3JlgpfxAnRVFzJ3-LykBgmlkgnY0gmlwhFPlR9KDaXA2kP6AAAAAAAAAAlBW__4my5iJc2VjcDI1NmsxoQLdUv9Eo9sxCt0tc_CheLOWnX59yHJtkBSOL7kpxdJ6GYN1ZHCCIyiEdWRwNoIjKA",
    ];

    /// [Sepolia bootnode ENRs](https://github.com/eth-clients/sepolia/blob/2bae9336a2d13998faf4c9f5574ccb2d15718721/metadata/bootstrap_nodes.yaml)
    #[cfg(any(feature = "network-sepolia", test))]
    const SEPOLIA_BOOTNODES: &'static [&'static str] = &[
        // > EF
        "enr:-Ku4QDZ_rCowZFsozeWr60WwLgOfHzv1Fz2cuMvJqN5iJzLxKtVjoIURY42X_YTokMi3IGstW5v32uSYZyGUXj9Q_IECh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIpEe5iJc2VjcDI1NmsxoQNHTpFdaNSCEWiN_QqT396nb0PzcUpLe3OVtLph-AciBYN1ZHCCIy0",
        "enr:-Ku4QHRyRwEPT7s0XLYzJ_EeeWvZTXBQb4UCGy1F_3m-YtCNTtDlGsCMr4UTgo4uR89pv11uM-xq4w6GKfKhqU31hTgCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIrFM7WJc2VjcDI1NmsxoQI4diTwChN3zAAkarf7smOHCdFb1q3DSwdiQ_Lc_FdzFIN1ZHCCIy0",
        "enr:-Ku4QOkvvf0u5Hg4-HhY-SJmEyft77G5h3rUM8VF_e-Hag5cAma3jtmFoX4WElLAqdILCA-UWFRN1ZCDJJVuEHrFeLkDh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhJK-AWeJc2VjcDI1NmsxoQLFcT5VE_NMiIC8Ll7GypWDnQ4UEmuzD7hF_Hf4veDJwIN1ZHCCIy0",
        "enr:-Ku4QH6tYsHKITYeHUu5kdfXgEZWI18EWk_2RtGOn1jBPlx2UlS_uF3Pm5Dx7tnjOvla_zs-wwlPgjnEOcQDWXey51QCh2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhIs7Mc6Jc2VjcDI1NmsxoQIET4Mlv9YzhrYhX_H9D7aWMemUrvki6W4J2Qo0YmFMp4N1ZHCCIy0",
        "enr:-Ku4QDmz-4c1InchGitsgNk4qzorWMiFUoaPJT4G0IiF8r2UaevrekND1o7fdoftNucirj7sFFTTn2-JdC2Ej0p1Mn8Ch2F0dG5ldHOIAAAAAAAAAACEZXRoMpCo_ujukAAAaf__________gmlkgnY0gmlwhKpA-liJc2VjcDI1NmsxoQMpHP5U1DK8O_JQU6FadmWbE42qEdcGlllR8HcSkkfWq4N1ZHCCIy0",

        // > Teku bootnode
        "enr:-Iu4QKvMF7Ne_RSQoZGvavTuZ1QA5_Pgeb0nq_hrjhU8s0UDV3KhcMXJkGwOWhsDGZL3ISjL0CTP-hfoTjZtEtCEwR4BgmlkgnY0gmlwhAOAaySJc2VjcDI1NmsxoQNta5b_bexSSwwrGW2Re24MjfMntzFd0f2SAxQtMj3ueYN0Y3CCIyiDdWRwgiMo",

        // > Lodestar
        "enr:-KG4QJejf8KVtMeAPWFhN_P0c4efuwu1pZHELTveiXUeim6nKYcYcMIQpGxxdgT2Xp9h-M5pr9gn2NbbwEAtxzu50Y8BgmlkgnY0gmlwhEEVkQCDaXA2kCoBBPnAEJg4AAAAAAAAAAGJc2VjcDI1NmsxoQLEh_eVvk07AQABvLkTGBQTrrIOQkzouMgSBtNHIRUxOIN1ZHCCIyiEdWRwNoIjKA",

        // > Unknown
        "enr:-Iq4QMCTfIMXnow27baRUb35Q8iiFHSIDBJh6hQM5Axohhf4b6Kr_cOCu0htQ5WvVqKvFgY28893DHAg8gnBAXsAVqmGAX53x8JggmlkgnY0gmlwhLKAlv6Jc2VjcDI1NmsxoQK6S-Cii_KmfFdUJL2TANL3ksaKUnNXvTCv1tLwXs0QgIN1ZHCCIyk",
        "enr:-L64QC9Hhov4DhQ7mRukTOz4_jHm4DHlGL726NWH4ojH1wFgEwSin_6H95Gs6nW2fktTWbPachHJ6rUFu0iJNgA0SB2CARqHYXR0bmV0c4j__________4RldGgykDb6UBOQAABx__________-CaWSCdjSCaXCEA-2vzolzZWNwMjU2azGhA17lsUg60R776rauYMdrAz383UUgESoaHEzMkvm4K6k6iHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo",
    ];

    /// [Holesky bootnode ENRs](https://github.com/eth-clients/holesky/blob/901c0f33339f8e79250a1053dc9d995270b666e9/metadata/bootstrap_nodes.yaml)
    #[cfg(any(feature = "network-holesky", test))]
    const HOLESKY_BOOTNODES: &'static [&'static str] = &[
        // EF
        "enr:-Ku4QFo-9q73SspYI8cac_4kTX7yF800VXqJW4Lj3HkIkb5CMqFLxciNHePmMt4XdJzHvhrCC5ADI4D_GkAsxGJRLnQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAhnTT-AQFwAP__________gmlkgnY0gmlwhLKAiOmJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyk",
        "enr:-Ku4QPG7F72mbKx3gEQEx07wpYYusGDh-ni6SNkLvOS-hhN-BxIggN7tKlmalb0L5JPoAfqD-akTZ-gX06hFeBEz4WoBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpAhnTT-AQFwAP__________gmlkgnY0gmlwhJK-DYCJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyk",
        "enr:-LK4QPxe-mDiSOtEB_Y82ozvxn9aQM07Ui8A-vQHNgYGMMthfsfOabaaTHhhJHFCBQQVRjBww_A5bM1rf8MlkJU_l68Eh2F0dG5ldHOIAADAAAAAAACEZXRoMpBpt9l0BAFwAAABAAAAAAAAgmlkgnY0gmlwhLKAiOmJc2VjcDI1NmsxoQJu6T9pclPObAzEVQ53DpVQqjadmVxdTLL-J3h9NFoCeIN0Y3CCIyiDdWRwgiMo",
        "enr:-Ly4QGbOw4xNel5EhmDsJJ-QhC9XycWtsetnWoZ0uRy381GHdHsNHJiCwDTOkb3S1Ade0SFQkWJX_pgb3g8Jfh93rvMBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpBpt9l0BAFwAAABAAAAAAAAgmlkgnY0gmlwhJK-DYCJc2VjcDI1NmsxoQOxKv9sv3zKF8GDewgFGGHKP5HCZZpPpTrwl9eXKAWGxIhzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
        // TEKU
        "enr:-KO4QCi3ZY4TM5KL7bAG6laSYiYelDWu0crvUjCXlyc_cwEfUpMIuARuMJYGxWe-UYYpHEw_aBbZ1u-4tHQ8imyI5uaCAsGEZXRoMpBprg6ZBQFwAP__________gmlkgnY0gmlwhKyuI_mJc2VjcDI1NmsxoQLoFG5-vuNX6N49vnkTBaA3ZsBDF8B30DGqWOGtRGz5w4N0Y3CCIyiDdWRwgiMo",
        // Sigma Prime
        "enr:-Le4QLoE1wFHSlGcm48a9ZESb_MRLqPPu6G0vHqu4MaUcQNDHS69tsy-zkN0K6pglyzX8m24mkb-LtBcbjAYdP1uxm4BhGV0aDKQabfZdAQBcAAAAQAAAAAAAIJpZIJ2NIJpcIQ5gR6Wg2lwNpAgAUHQBwEQAAAAAAAAADR-iXNlY3AyNTZrMaEDPMSNdcL92uNIyCsS177Z6KTXlbZakQqxv3aQcWawNXeDdWRwgiMohHVkcDaCI4I",
        // Lodestar
        "enr:-KG4QC9Wm32mtzB5Fbj2ri2TEKglHmIWgvwTQCvNHBopuwpNAi1X6qOsBg_Z1-Bee-kfSrhzUQZSgDUyfH5outUprtoBgmlkgnY0gmlwhHEel3eDaXA2kP6AAAAAAAAAAlBW__4Srr-Jc2VjcDI1NmsxoQO7KE63Z4eSI55S1Yn7q9_xFkJ1Wt-a3LgiXuKGs19s0YN1ZHCCIyiEdWRwNoIjKA",
    ];

    /// [Hoodi bootnode ENRs](https://github.com/eth-clients/hoodi/blob/12da21411825d4c998dc71daf3b553c46e90a1a7/metadata/bootstrap_nodes.yaml)
    #[cfg(any(feature = "network-hoodi", test))]
    const HOODI_BOOTNODES: &'static [&'static str] = &[
        // EF
        "enr:-Mq4QLkmuSwbGBUph1r7iHopzRpdqE-gcm5LNZfcE-6T37OCZbRHi22bXZkaqnZ6XdIyEDTelnkmMEQB8w6NbnJUt9GGAZWaowaYh2F0dG5ldHOIABgAAAAAAACEZXRoMpDS8Zl_YAAJEAAIAAAAAAAAgmlkgnY0gmlwhNEmfKCEcXVpY4IyyIlzZWNwMjU2azGhA0hGa4jZJZYQAS-z6ZFK-m4GCFnWS8wfjO0bpSQn6hyEiHN5bmNuZXRzAIN0Y3CCIyiDdWRwgiMo",
        "enr:-Ku4QLVumWTwyOUVS4ajqq8ZuZz2ik6t3Gtq0Ozxqecj0qNZWpMnudcvTs-4jrlwYRQMQwBS8Pvtmu4ZPP2Lx3i2t7YBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpBd9cEGEAAJEP__________gmlkgnY0gmlwhNEmfKCJc2VjcDI1NmsxoQLdRlI8aCa_ELwTJhVN8k7km7IDc3pYu-FMYBs5_FiigIN1ZHCCIyk",
        "enr:-LK4QAYuLujoiaqCAs0-qNWj9oFws1B4iy-Hff1bRB7wpQCYSS-IIMxLWCn7sWloTJzC1SiH8Y7lMQ5I36ynGV1ASj4Eh2F0dG5ldHOIYAAAAAAAAACEZXRoMpDS8Zl_YAAJEAAIAAAAAAAAgmlkgnY0gmlwhIbRilSJc2VjcDI1NmsxoQOmI5MlAu3f5WEThAYOqoygpS2wYn0XS5NV2aYq7T0a04N0Y3CCIyiDdWRwgiMo",
        "enr:-Ku4QIC89sMC0o-irosD4_23lJJ4qCGOvdUz7SmoShWx0k6AaxCFTKviEHa-sa7-EzsiXpDp0qP0xzX6nKdXJX3X-IQBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpBd9cEGEAAJEP__________gmlkgnY0gmlwhIbRilSJc2VjcDI1NmsxoQK_m0f1DzDc9Cjrspm36zuRa7072HSiMGYWLsKiVSbP34N1ZHCCIyk",
        "enr:-Ku4QNkWjw5tNzo8DtWqKm7CnDdIq_y7xppD6c1EZSwjB8rMOkSFA1wJPLoKrq5UvA7wcxIotH6Usx3PAugEN2JMncIBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpBd9cEGEAAJEP__________gmlkgnY0gmlwhIbHuBeJc2VjcDI1NmsxoQP3FwrhFYB60djwRjAoOjttq6du94DtkQuaN99wvgqaIYN1ZHCCIyk",
        "enr:-OS4QMJGE13xEROqvKN1xnnt7U-noc51VXyM6wFMuL9LMhQDfo1p1dF_zFdS4OsnXz_vIYk-nQWnqJMWRDKvkSK6_CwDh2F0dG5ldHOIAAAAADAAAACGY2xpZW502IpMaWdodGhvdXNljDcuMC4wLWJldGEuM4RldGgykNLxmX9gAAkQAAgAAAAAAACCaWSCdjSCaXCEhse4F4RxdWljgiMqiXNlY3AyNTZrMaECef77P8k5l3PC_raLw42OAzdXfxeQ-58BJriNaqiRGJSIc3luY25ldHMAg3RjcIIjKIN1ZHCCIyg",
        // Teku
        "enr:-LK4QDwhXMitMbC8xRiNL-XGMhRyMSOnxej-zGifjv9Nm5G8EF285phTU-CAsMHRRefZimNI7eNpAluijMQP7NDC8kEMh2F0dG5ldHOIAAAAAAAABgCEZXRoMpDS8Zl_YAAJEAAIAAAAAAAAgmlkgnY0gmlwhAOIT_SJc2VjcDI1NmsxoQMoHWNL4MAvh6YpQeM2SUjhUrLIPsAVPB8nyxbmckC6KIN0Y3CCIyiDdWRwgiMo",
        "enr:-LK4QPYl2HnMPQ7b1es6Nf_tFYkyya5bj9IqAKOEj2cmoqVkN8ANbJJJK40MX4kciL7pZszPHw6vLNyeC-O3HUrLQv8Mh2F0dG5ldHOIAAAAAAAAAMCEZXRoMpDS8Zl_YAAJEAAIAAAAAAAAgmlkgnY0gmlwhAMYRG-Jc2VjcDI1NmsxoQPQ35tjr6q1qUqwAnegQmYQyfqxC_6437CObkZneI9n34N0Y3CCIyiDdWRwgiMo",
        // Lodestar
        "enr:-KG4QJk_4IQHQw3DAdKIuGcEauKU8-nmRPPMj_hIQPRHmsFGMPPeOj6_xX09aHCndOzLnOZimVRzNM56_EQWYVbEpJMBgmlkgnY0gmlwhLkvrBODaXA2kP6AAAAAAAAAAhY-__4PR6OJc2VjcDI1NmsxoQPU7g2jQGTz8BYbB2vLTb39S_PrcZAehwMM0b3bWsM5rIN1ZHCCIyiEdWRwNoIjKA",
    ];

    #[must_use]
    pub fn chain_config(self) -> ChainConfig {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => ChainConfig::mainnet(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => ChainConfig::sepolia(),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => ChainConfig::holesky(),
            #[cfg(any(feature = "network-hoodi", test))]
            Self::Hoodi => ChainConfig::hoodi(),
        }
    }

    pub async fn genesis_checkpoint_provider<P: Preset>(
        self,
        client: &Client,
        store_directory: impl AsRef<Path> + Send,
        genesis_download_url: Option<RedactingUrl>,
    ) -> Result<AnchorCheckpointProvider<P>> {
        let config = &self.chain_config();

        #[cfg(any(
            feature = "network-sepolia",
            feature = "network-holesky",
            feature = "network-hoodi",
            test
        ))]
        let load_genesis_checkpoint = |default_download_url: &str| {
            load_or_download_genesis_checkpoint(
                config,
                client,
                store_directory,
                genesis_download_url.unwrap_or_else(|| {
                    default_download_url
                        .parse()
                        .expect("hard-coded genesis state download URL should be valid")
                }),
            )
        };

        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => predefined_chains::mainnet::<P>(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => load_genesis_checkpoint(
                "https://github.com/eth-clients/sepolia/raw/ab4137ed529bec09fbffd914ff8da70ca8082c0f/bepolia/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Sepolia genesis state")?,
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => load_genesis_checkpoint(
                "https://github.com/eth-clients/holesky/raw/613c333b66c3787cb0418948be82d283770bd44a/custom_config_data/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Holesky genesis state")?,
            #[cfg(any(feature = "network-hoodi", test))]
            Self::Hoodi => load_genesis_checkpoint(
                "https://github.com/eth-clients/hoodi/raw/2b03cffba84b50759b3476a69334fac8412e217c/metadata/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Hoodi genesis state")?,
        }
        .pipe(Ok)
    }

    #[must_use]
    pub fn genesis_deposit_tree(self) -> DepositTree {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => Self::mainnet_genesis_deposit_tree(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => DepositTree {
                last_added_block_number: 1_273_020,
                ..DepositTree::default()
            },
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => DepositTree::default(),
            #[cfg(any(feature = "network-hoodi", test))]
            Self::Hoodi => DepositTree::default(),
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
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => Self::SEPOLIA_BOOTNODES,
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => Self::HOLESKY_BOOTNODES,
            #[cfg(any(feature = "network-hoodi", test))]
            Self::Hoodi => Self::HOODI_BOOTNODES,
        }
        .iter()
        .copied()
        .map(str::parse)
        .map(|result| result.expect("bootnode ENR should be valid"))
        .collect()
    }
}

async fn load_or_download_genesis_checkpoint<P: Preset>(
    config: &ChainConfig,
    client: &Client,
    store_directory: impl AsRef<Path> + Send,
    download_url: RedactingUrl,
) -> Result<WithOrigin<FinalizedCheckpoint<P>>> {
    let genesis_state_path = store_directory.as_ref().join("genesis_state.ssz");

    let ssz_bytes = match fs_err::tokio::read(genesis_state_path.as_path()).await {
        Ok(bytes) => {
            info!(
                "loading genesis state from file: {}…",
                genesis_state_path.display()
            );
            bytes.into()
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            info!("downloading genesis state from {download_url}…");

            let bytes = client
                .get(download_url.into_url())
                .timeout(Duration::from_secs(600))
                .send()
                .await?
                .bytes()
                .await?;

            fs_err::create_dir_all(&store_directory)?;
            fs_err::tokio::write(genesis_state_path, &bytes).await?;

            bytes
        }
        Err(error) => bail!(error),
    };

    let state = Arc::from_ssz(config, ssz_bytes)?;
    let block = Arc::new(genesis::beacon_block(&state));

    info!("genesis state loaded at slot: {}", state.slot());

    Ok(WithOrigin::new_from_genesis(FinalizedCheckpoint {
        block,
        state,
    }))
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use types::{preset::Mainnet, traits::BeaconState as _};

    use super::*;

    #[test_case(PredefinedNetwork::Mainnet)]
    fn genesis_state_and_deposit_tree_valid(predefined_network: PredefinedNetwork) {
        assert_deposit_tree_valid::<Mainnet>(predefined_network)
    }

    fn assert_deposit_tree_valid<P: Preset>(predefined_network: PredefinedNetwork) {
        let genesis_checkpoint_provider = predefined_network
            .genesis_checkpoint_provider::<P>(&Client::new(), "", None)
            .pipe(futures::executor::block_on)
            .expect("this test should not load files or access the network");

        let state = genesis_checkpoint_provider.checkpoint().value.state;
        let deposit_tree = predefined_network.genesis_deposit_tree();

        assert_eq!(state.eth1_data().deposit_count, deposit_tree.deposit_count);
        assert_eq!(state.eth1_deposit_index(), deposit_tree.deposit_count);
    }
}
