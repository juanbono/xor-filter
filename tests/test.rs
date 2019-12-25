use xor_filter::Xor8;

#[test]
fn contains_works_when_elem_is_present() {
    let filter = Xor8::new(vec![1, 29, 7]);
    assert!(filter.contains(1));
    assert!(filter.contains(29));
    assert!(filter.contains(7));
}

#[test]
fn contains_works_when_elem_is_not_present() {
    let filter = Xor8::new(vec![1, 2, 3]);
    assert!(!filter.contains(0));
    assert!(!filter.contains(12));
    assert!(!filter.contains(7));
}

#[test]
fn filter_can_be_empty() {
    let filter = Xor8::new(Vec::new());
    assert!(!filter.contains(2));
    assert!(!filter.contains(0));
    assert!(!filter.contains(29));
}
