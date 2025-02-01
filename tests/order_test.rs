mod common;

use acme_client::{
    challenge::{ChallengeStatus, ChallengeType},
    order::Order,
};
use common::create_test_account;

#[test]
fn test_new_order() {
    let mut account = create_test_account();
    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();

    assert_ne!(order.order_url, "");

    let challenge = order.get_challenge(ChallengeType::Dns01).unwrap();

    assert_eq!(challenge.challenge_type, ChallengeType::Dns01);
}

#[test]
fn test_validate_challenge() {
    let mut account = create_test_account();
    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();

    let challenge = order.get_challenge(ChallengeType::Dns01).unwrap();
    challenge.validate(&mut account).unwrap();

    assert_eq!(challenge.status, ChallengeStatus::Valid);
}

#[test]
fn test_finalize_order() {
    let mut account = create_test_account();

    let mut order = Order::new(&mut account, "xiuzhe.xyz").unwrap();
    order
        .finalize(&account)
        .unwrap()
        .download_certificate(&account, "/home/yuwhisper/projects/acme-client/cert.cert")
        .unwrap();
}
