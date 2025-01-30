mod order_test;

#[test]
fn test_create_account() {
    let storage = acme_client::storage::FileStorage::open("/home/yuwhisper/projects/acme-client/test_storage").unwrap();
    let dir = acme_client::directory::Directory::new(&storage,"https://acme-staging-v02.api.letsencrypt.org/directory").unwrap();
    let key_pair = acme_client::key_pair::KeyPair::new(&storage, "RSA", Some(2048)).unwrap();
    let email = "yu.whisper.personal@gmail.com";

    let account = acme_client::account::Account::new(Box::new(storage), dir, key_pair, email).unwrap(); 

    assert_ne!(account.account_url, "");
}
