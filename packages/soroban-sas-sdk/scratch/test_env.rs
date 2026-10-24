use soroban_sdk::{Env, Address};
fn extract_env(addr: &Address) -> &Env {
    addr.env()
}
