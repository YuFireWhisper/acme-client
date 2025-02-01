use acme_client::{
    account::Account,
    challenge::{ChallengeStatus, ChallengeType},
    order::Order,
};

fn get_account() -> Account {
    let storage = acme_client::storage::FileStorage::open(
        "/home/yuwhisper/projects/acme-client/test_storage",
    )
    .unwrap();
    let dir = acme_client::directory::Directory::new(
        &storage,
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    )
    .unwrap();
    let key_pair = acme_client::key_pair::KeyPair::new(
        &storage,
        "RSA",
        Some(2048),
        Some("/home/yuwhisper/projects/acme-client/test_storage/acct_key_pair"),
    )
    .unwrap();
    let email = "yu.whisper.personal@gmail.com";

    acme_client::account::Account::new(Box::new(storage), dir, key_pair, email).unwrap()
}

#[test]
fn test_new_order() {
    let mut account = get_account();
    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();

    assert_ne!(order.order_url, "");

    println!("Order Challenge: {:#?}", order.challenges);

    let challenge = order.get_challenge(ChallengeType::Dns01).unwrap();
    let zh_message = challenge.get_instructions("zh-tw");

    println!("zh-tw: {}", zh_message);

    assert_eq!(challenge.challenge_type, ChallengeType::Dns01);
}

#[test]
fn test_validate_challenge() {
    let mut account = get_account();
    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();
    println!("Order URL: {}", order.order_url);

    let challenge = order.get_challenge(ChallengeType::Dns01).unwrap();
    challenge.validate(&mut account).unwrap();

    assert_eq!(challenge.status, ChallengeStatus::Valid);
}

#[test]
fn test_finalize_order() {
    let mut account = get_account();

    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();
    order
        .finalize(&account)
        .unwrap()
        .download_certificate(&account, "/home/yuwhisper/projects/acme-client/cert.cert")
        .unwrap();
}
