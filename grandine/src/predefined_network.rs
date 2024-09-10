use core::time::Duration;
use std::{io::ErrorKind, path::Path, sync::Arc};

use anyhow::{bail, Context as _, Result};
use deposit_tree::DepositTree;
use fork_choice_control::checkpoint_sync;
use genesis::AnchorCheckpointProvider;
use tracing::info;
use p2p::{Enr, NetworkConfig};
use reqwest::{Client, Url};
use ssz::SszRead as _;
use strum::Display;
use tap::Pipe as _;
use types::{
    config::Config as ChainConfig,
    nonstandard::{FinalizedCheckpoint, WithOrigin},
    preset::Preset,
};

#[cfg(any(feature = "network-mainnet", test))]
use ::{hex_literal::hex, types::phase0::primitives::H256};

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub enum PredefinedNetwork {
    #[cfg(any(feature = "network-mainnet", test))]
    Mainnet,
    #[cfg(any(feature = "network-goerli", test))]
    Goerli,
    #[cfg(any(feature = "network-sepolia", test))]
    Sepolia,
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
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => ChainConfig::goerli(),
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => ChainConfig::sepolia(),
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => ChainConfig::holesky(),
        }
    }

    pub async fn anchor_checkpoint_provider<P: Preset>(
        self,
        client: &Client,
        store_directory: impl AsRef<Path> + Send,
        checkpoint_sync_url: Option<Url>,
        genesis_download_url: Option<Url>,
    ) -> Result<AnchorCheckpointProvider<P>> {
        let config = &self.chain_config();

        #[cfg(any(
            feature = "network-goerli",
            feature = "network-sepolia",
            feature = "network-holesky",
            test
        ))]
        let load_anchor_checkpoint = |default_download_url: &str| {
            load_or_download_anchor_checkpoint(
                config,
                client,
                store_directory,
                genesis_download_url.unwrap_or_else(|| {
                    default_download_url
                        .try_into()
                        .expect("hard-coded genesis state download URL should be valid")
                }),
                checkpoint_sync_url,
            )
        };

        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => predefined_chains::mainnet::<P>(),
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => load_anchor_checkpoint(
                "https://github.com/eth-clients/goerli/raw/397ecd128e8162fa9b352cd28cdea77d64502629/prater/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Goerli genesis state")?,
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => load_anchor_checkpoint(
                "https://github.com/eth-clients/sepolia/raw/ab4137ed529bec09fbffd914ff8da70ca8082c0f/bepolia/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Sepolia genesis state")?,
            #[cfg(any(feature = "network-holesky", test))]
            Self::Holesky => load_anchor_checkpoint(
                "https://github.com/eth-clients/holesky/raw/613c333b66c3787cb0418948be82d283770bd44a/custom_config_data/genesis.ssz",
            )
            .await
            .map(AnchorCheckpointProvider::Custom)
            .context("failed to load Holesky genesis state")?,
        }
        .pipe(Ok)
    }

    #[must_use]
    pub fn genesis_deposit_tree(self) -> DepositTree {
        match self {
            #[cfg(any(feature = "network-mainnet", test))]
            Self::Mainnet => Self::mainnet_genesis_deposit_tree(),
            // TODO(Grandine Team): The remaining `DepositTree`s are incorrect. `validator` will be
            //                      unable to construct valid deposit proofs when using them.
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => DepositTree {
                last_added_block_number: 4_367_322,
                ..DepositTree::default()
            },
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => DepositTree {
                last_added_block_number: 1_273_020,
                ..DepositTree::default()
            },
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
            #[cfg(any(feature = "network-goerli", test))]
            Self::Goerli => Self::GOERLI_BOOTNODES,
            #[cfg(any(feature = "network-sepolia", test))]
            Self::Sepolia => Self::SEPOLIA_BOOTNODES,
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

async fn load_or_download_anchor_checkpoint<P: Preset>(
    config: &ChainConfig,
    client: &Client,
    store_directory: impl AsRef<Path> + Send,
    download_url: Url,
    checkpoint_sync_url: Option<Url>,
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
            if let Some(url) = checkpoint_sync_url {
                info!("downloading genesis state from {url}…");

                let finalized_checkpoint =
                    checkpoint_sync::load_finalized_from_remote(config, client, &url).await?;

                return Ok(WithOrigin::new_from_checkpoint(finalized_checkpoint));
            }

            info!("downloading genesis state from {download_url}…");

            let bytes = client
                .get(download_url)
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

    let state = Arc::from_ssz(config, ssz_bytes)?;
    let block = Arc::new(genesis::beacon_block(&state));

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
        let anchor_checkpoint_provider = predefined_network
            .anchor_checkpoint_provider::<P>(&Client::new(), "", None, None)
            .pipe(futures::executor::block_on)
            .expect("this test should not load files or access the network");

        let state = anchor_checkpoint_provider.checkpoint().value.state;
        let deposit_tree = predefined_network.genesis_deposit_tree();

        assert_eq!(state.eth1_data().deposit_count, deposit_tree.deposit_count);
        assert_eq!(state.eth1_deposit_index(), deposit_tree.deposit_count);
    }
}
