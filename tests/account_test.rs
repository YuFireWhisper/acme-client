mod common;

use common::create_test_account;

#[test]
fn test_create_account() {
    let account = create_test_account();

    assert_ne!(account.account_url, "");
}
