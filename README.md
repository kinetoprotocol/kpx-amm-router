# kpx-amm-router — KPXRouterGateway

**AXIOLEDGER `kinetoprotocol` ($KPX) — Central Routing Gateway**

Routes: Cross-chain Bridge · AMM Swap · RWA Treasury · Dark Pool

## Security model
- ReentrancyGuard on all state-changing functions
- VRQ blacklist pre-check before every operation
- MPC 2/3 threshold for bridge execution
- No EOA admin — owner is TreasuryDAO multisig

## Deploy

```bash
cp .env.example .env  # fill in vars
forge install OpenZeppelin/openzeppelin-contracts --no-commit
forge install foundry-rs/forge-std --no-commit

# Local
forge script script/DeployKPXRouter.s.sol:DeployKPXRouter \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974... --broadcast -vvvv

# Sepolia (via CI — set GitHub Actions Secrets first)
# Actions → KPX AMM Router CI/CD → Run workflow → dry_run=false
```

## Required Secrets

| Secret | Description |
|---|---|
| `SEPOLIA_RPC_URL` | Sepolia RPC endpoint |
| `DEPLOYER_PRIVATE_KEY` | Deployer EOA key |
| `ETHERSCAN_API_KEY` | Contract verification |

## ⚠️ Pre-mainnet checklist
- [ ] Replace `MockVRQVerifier` with production `IVRQVerifier`
- [ ] Replace `MockDarkPool` with production `IKPXDarkPool`
- [ ] Transfer `treasuryDao` to 5/7 multisig
- [ ] Slither + Mythril full audit pass
- [ ] Add LP contracts (LiquidityPool + EmissionController)
