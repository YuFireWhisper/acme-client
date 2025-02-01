use acme_client::account::{Account, AccountBuilder};

pub fn create_test_account() -> Account {
    let storage_path = "/home/yuwhisper/projects/acme-client/test_storage";
    let dir_url = "https://acme-staging-v02.api.letsencrypt.org/directory";
    let email = "yu.whisper.personal@gmail.com";

    AccountBuilder::new(email)
        .storage_path(storage_path)
        .dir_url(dir_url)
        .build()
        .unwrap()
}
