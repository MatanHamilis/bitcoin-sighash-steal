# Bitcoin Scan Sighash

This tool is an educational source to learn more about Bitcoin's `SIGHASH_SINGLE` bug.
You can read the whole post [here](https://github.com/MatanHamilis/sighash_post)

## Purpose

This tool is intended to be used to steal coins from `SIGHASH_SINGLE` vulnerable addresses.
To use it you'll have to provide your (the attacker) Bitcoin address, the `txid` and `vout` of a UTXO owned by a vulnerable address and the `scriptSig` which includes the vulnerable signature (i.e. the signature signing "1") as signed by the vulnerable address.

## Requirements

To use this tool, you'll first have to run your own node of Bitcoin.
If you already have one, move to the next step.
Otherwise,  follow the instruction from  [Bitcoin core's website](https://bitcoincore.org/).
Notice it might take a while to synchronize your node.
In the end of the process your Bitcoin node should be up and running.

This tool is running on testnet-enabled nodes (by connecting to testnet port - `18332` on your node).
To run your node on testnet either add `testnet=1` line to bitcoin-core's configuration file or run your node with the `-testnet` flag.
This is intentional to prevent newcomers from accidentally running this node on mainnet.
You can configure it to run on mainnet using the configuration flags.

## Running

Use `cargo build --release` to build the program.
Nest, use `cargo run --release -- --help` to list all options available.
Currently the following options are available:

1. `--address` - To specify the address of your bitcoin node, typically it listens to RPC commands on `http://127.0.0.1:18332` on testnet. To use it on mainnet you'll probably have to specify `http://127.0.0.1:8332`.
2. `--bitcoin-dir` - This is used to extract the credentials needed to access your bitcoin node. On Linux/MacOS it is `~/.bitcoin` by default and on windows that is `%APPDATA%/Bitcoin` by default.
3. `--log-file` - If specified the output will be written to the given log file, otherwise will be written to `stderr`.
4. `--attacker-address` is the Bitcoin address of the attacker.
5. `--steal-txid` is the `txid` of a UTXO owned by the victim.
6. `--vuln-script` is the Bitcoin `scriptSig` which contains the victim's vulnerable signature on "1".

**DISCLAIMER**: I haven't tested this on anything but Linux, so feel free to open issues.
