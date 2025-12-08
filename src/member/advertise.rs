use std::{collections::{BTreeMap, BTreeSet}, fs, time::Duration};
use bluer::adv::Advertisement;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::{Aead, OsRng, rand_core::RngCore, AeadCore}};
use base64::{Engine, engine::general_purpose};
use tokio::{io::{BufReader, AsyncBufReadExt}, time::sleep};
use uuid::{uuid, Uuid};

type NonceSize = AeadCore::NonceSize;

#[tokio::main]
pub(crate) async fn main() -> bluer::Result<()> {
    env_logger::init();

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    println!("Advertising on Bluetooth adapter {} with address {}", adapter.name(), adapter.address().await?);

    let key: [u8; 32] = general_purpose::STANDARD
        .decode(fs::read_to_string("group-key")?.trim())
        .expect("invalid key file")
        .try_into()
        .expect("invalid key");
    let key = Key::from_slice(&key);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce: &Nonce<NonceSize> = Nonce::from_slice(&nonce_bytes);

    let asset_id = fs::read_to_string("asset-tag")?.trim().to_string();
    let asset_id_hash = blake3::hash(&asset_id.as_bytes());

    let ciphertext = cipher.encrypt(nonce, asset_id_hash.as_bytes()[..]).unwrap();

    let mut payload = Vec::new();
    payload.push(0xA1);
    payload.extend_from_slice(&nonce_bytes);    
    payload.extend_from_slice(&ciphertext);

    const SERVICE_UUID: Uuid = uuid!("c193b907-6f78-4769-aafa-83e807c9c0a6");

    let mut service_uuids = BTreeSet::new();
    service_uuids.insert(SERVICE_UUID);

    let mut service_data = BTreeMap::new();
    service_data.insert(SERVICE_UUID, payload);

    let advertisement = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids,
        service_data,
        discoverable: Some(true),
        ..Default::default()
    };

    println!("{:?}", &advertisement);

    let handle = adapter.advertise(advertisement).await?;

    println!("Press enter to quit");

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let _ = lines.next_line().await;

    println!("Removing advertisement");
    drop(handle);
    sleep(Duration::from_secs(1)).await;

    Ok(())
}