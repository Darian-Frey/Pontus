//! Scope enforcement contract (F-007): the public API must refuse out-of-scope
//! targets and must not offer a way to build an empty (allow-everything) scope.

use pontus_core::scope::{Scope, ScopeError};

fn ip(s: &str) -> std::net::IpAddr {
    s.parse().unwrap()
}

#[test]
fn in_scope_allowed_out_of_scope_refused() {
    let scope = Scope::parse(["192.168.0.0/16", "2001:db8::/32"]).unwrap();
    assert!(scope.ensure(ip("192.168.5.5")).is_ok());
    assert!(scope.ensure(ip("2001:db8::dead")).is_ok());
    assert!(matches!(scope.ensure(ip("10.0.0.1")), Err(ScopeError::OutOfScope(_))));
    assert!(matches!(scope.ensure(ip("2001:dead::1")), Err(ScopeError::OutOfScope(_))));
}

#[test]
fn empty_scope_is_rejected() {
    assert!(matches!(Scope::parse(Vec::<String>::new()), Err(ScopeError::Empty)));
    assert!(matches!(Scope::new(vec![]), Err(ScopeError::Empty)));
}

#[test]
fn bare_host_and_garbage_specs_handled() {
    let scope = Scope::parse(["203.0.113.7"]).unwrap();
    assert!(scope.contains(ip("203.0.113.7")));
    assert!(!scope.contains(ip("203.0.113.8")));
    assert!(matches!(Scope::parse(["not-an-ip"]), Err(ScopeError::Invalid(_))));
}
