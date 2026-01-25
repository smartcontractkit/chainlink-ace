import { spawnSync } from "node:child_process";

const target = process.argv[2];
const passthroughIdx = process.argv.indexOf("--");
const extraArgs = passthroughIdx === -1 ? [] : process.argv.slice(passthroughIdx + 1);

const scripts = {
  simple: "./script/DeploySimpleComplianceToken.s.sol",
  erc20: "./script/DeployComplianceTokenERC20.s.sol",
  erc3643: "./script/DeployComplianceTokenERC3643.s.sol",
};

const scriptPath = scripts[target];
if (!scriptPath) {
  console.error(`Unknown deploy target "${target}". Use one of: ${Object.keys(scripts).join(", ")}`);
  process.exit(1);
}

const rpcUrl = process.env.RPC_URL || process.env.ETH_RPC_URL || "http://localhost:8545";

const args = ["script", scriptPath, "--via-ir", "--broadcast", "--rpc-url", rpcUrl];
if (process.env.PRIVATE_KEY) args.push("--private-key", process.env.PRIVATE_KEY);
args.push(...extraArgs);

const res = spawnSync("forge", args, { stdio: "inherit", shell: true });
process.exit(res.status ?? 1);

