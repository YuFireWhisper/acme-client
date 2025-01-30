use acme_client::{account::Account, order::Order};

fn get_account() -> Account {
        let storage = acme_client::storage::FileStorage::open("/home/yuwhisper/projects/acme-client/test_storage").unwrap();
    let dir = acme_client::directory::Directory::new(&storage,"https://acme-staging-v02.api.letsencrypt.org/directory").unwrap();
    let key_pair = acme_client::key_pair::KeyPair::new(&storage, "RSA", Some(2048)).unwrap();
    let email = "yu.whisper.personal@gmail.com";

    acme_client::account::Account::new(Box::new(storage), dir, key_pair, email).unwrap()
}

#[test]
fn test_new_order() {
    let mut account = get_account();
    let order = Order::new(&mut account, "xiuzhe.xyz").unwrap();

    assert_ne!(order.order_url, "");
}
