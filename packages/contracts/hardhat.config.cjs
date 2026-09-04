require("@nomicfoundation/hardhat-viem");
require("@nomicfoundation/hardhat-network-helpers");

/**
 * FairProof contract toolchain.
 *
 * The permissioned Besu network uses a zero gas price and a high block gas
 * limit (development plan Section 7.1), because on-chain Poseidon
 * accumulation and Groth16 verification are both expensive. The local test
 * network mirrors that so gas never distorts a test result.
 */
module.exports = {
  solidity: {
    version: "0.8.28",
    settings: {
      // runs=1 optimises for deployed size rather than call cost.
      // Poseidon's constant tables dominate the bytecode, and on a
      // permissioned free-gas chain size matters more than marginal gas.
      optimizer: { enabled: true, runs: 1 },
    },
  },
  networks: {
    hardhat: {
      blockGasLimit: 100_000_000,
      gasPrice: 0,
      initialBaseFeePerGas: 0,
      allowUnlimitedContractSize: false,
    },
    besu: {
      url: process.env.BESU_RPC_URL || "http://127.0.0.1:8545",
      chainId: Number(process.env.FAIRPROOF_CHAIN_ID || 20260),
      gasPrice: 0,
    },
  },
  paths: {
    sources: "contracts",
    tests: "test",
    cache: "cache",
    artifacts: "artifacts",
  },
};
