# ZK-SNARK Implementation Attack Techniques

- **Sprout Counterfeiting Vulnerability (CVE-2019-7167)**
  **Project**: Zcash (Sprout)
  **Summary**: A flaw in the original trusted setup left “toxic waste,” breaking soundness and allowing an attacker to create fake proofs and mint unlimited ZEC. Quietly fixed in 2018 before any exploitation.
  **Cause / Vulnerability**: Unsound trusted-setup parameters
  **URL**: <https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/>

- **Merkle-Root Insertion Constraint Omission**
  **Project**: Aztec 2.0
  **Summary**: The root-tree circuit did not constrain the insertion index; a malicious rollup provider could insert leaves at arbitrary positions and render future rollups unverifiable, halting the system.
  **Cause / Vulnerability**: Missing constraint (completeness/soundness break)
  **URL**: <https://aztec.network/blog/vulnerabilities-patched-in-aztec-2-0>

- **tree_index Bit-Length Bypass & Note Re-use**
  **Project**: Aztec 2.0
  **Summary**: The 32-bit range check on `tree_index` was absent. By manipulating high bits, an attacker could reuse the same note multiple times, enabling double-spending.
  **Cause / Vulnerability**: Under-constrained input (soundness break)
  **URL**: <https://aztec.network/blog/vulnerabilities-patched-in-aztec-2-0>

- **Deterministic PRNG & Blinding-Factor Leakage**
  **Project**: Aztec 2.0
  **Summary**: A Mersenne Twister PRNG was used for randomness; if the seed leaked, future random values became predictable, exposing blinding factors and compromising privacy.
  **Cause / Vulnerability**: Insecure randomness
  **URL**: <https://aztec.network/blog/vulnerabilities-patched-in-aztec-2-0>

- **Frozen Heart (Fiat–Shamir Challenge Manipulation)**
  **Project**: PlonK, Bulletproofs, gnark, snarkJS and others
  **Summary**: Improper Fiat–Shamir hashing allowed a prover to bias or predict challenge values, forging proofs for false statements across multiple libraries.
  **Cause / Vulnerability**: Faulty Fiat–Shamir implementation
  **URL**: <https://blog.trailofbits.com/2022/04/18/the-frozen-heart-vulnerability-in-plonk/>

- **Bulletproofs Fiat–Shamir Mishandling (CVE-2022-29566)**
  **Project**: Bulletproofs
  **Summary**: The original Bulletproofs paper omitted parts of the public input when hashing, enabling the Frozen Heart–style forgery in many implementations.
  **Cause / Vulnerability**: Incomplete Fiat–Shamir transform
  **URL**: <https://nvd.nist.gov/vuln/detail/CVE-2022-29566>

- **2-Cycle Nova Soundness Flaw**
  **Project**: Nova IVC
  **Summary**: A soundness bug let attackers fabricate proofs for extremely long iterative computations (e.g., a 2^75-step VDF) in seconds. Patched after academic disclosure.
  **Cause / Vulnerability**: Missing constraints in cycle composition
  **URL**: <https://eprint.iacr.org/2023/969>

- **Public-Input Field-Bound Check Missing**
  **Project**: Semaphore
  **Summary**: The circuit failed to ensure that public inputs were within the field range; oversized values could break verification and trigger denial-of-service.
  **Cause / Vulnerability**: Range check omission (completeness bug)
  **URL**: <https://github.com/semaphore-protocol/semaphore/issues/90>

- **Under-Constrained ECDSA Verification Gadget**
  **Project**: circom / circomlib
  **Summary**: Point-doubling constraints were missing, allowing invalid signatures to pass and enabling proof forgery.
  **Cause / Vulnerability**: Constraint omission (soundness break)
  **URL**: <https://veridise.com/wp-content/uploads/2023/02/VAR-circom-bigint.pdf>

- **Trusted Setup Phase-1 Parameter Flaw**
  **Project**: Aleo (Powers of Tau)
  **Summary**: A discrete-log relation unintentionally persisted in G2 elements, weakening the CRS and risking trapdoor exposure. Fixed per Least Authority audit.
  **Cause / Vulnerability**: Faulty parameter generation in trusted setup
  **URL**: <https://leastauthority.com/blog/audits/audit-of-aleo-trusted-setup-phase-1/>

- **Un-normalized Point & Large-Integer Inputs**
  **Project**: Succinct Telepathy
  **Summary**: Lack of point normalization and integer range checks could cause proof failure and permanently lock user funds.
  **Cause / Vulnerability**: Input validation missing (completeness/soundness)
  **URL**: <https://github.com/Zellic/publications/raw/master/Succinct%20Telepathy%20-%20Zellic%20Audit%20Report.pdf>

- **Insufficient Proof Verification (Packed-Amount Manipulation)**
  **Project**: zkSync Era
  **Summary**: The `mantissa` field lacked constraints; attackers could craft proofs that alter transaction amounts. Patched on 2023-11-07.
  **Cause / Vulnerability**: Circuit constraint omission (soundness break)
  **URL**: <https://medium.com/immunefi/zksync-insufficient-proof-verification-bugfix-review-dcd57944d0e2>
