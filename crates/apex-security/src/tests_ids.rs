use super::ids::uuid7;
use super::is_lowercase_uuidv7;

#[test]
fn generated_finding_ids_are_uuidv7_and_unique_for_a_burst() {
    let first = uuid7().unwrap();
    let second = uuid7().unwrap();
    assert!(is_lowercase_uuidv7(&first));
    assert!(is_lowercase_uuidv7(&second));
    assert_ne!(first, second);
}
