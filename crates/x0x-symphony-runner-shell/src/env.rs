//! Environment allow-list construction for child processes.

use std::collections::{BTreeMap, BTreeSet};

use x0x_symphony_core::SessionContext;

use crate::{
    error::{Error, Result},
    RunnerSpec,
};

pub(crate) fn build_child_env(
    spec: &RunnerSpec,
    ctx: &SessionContext,
) -> Result<BTreeMap<String, String>> {
    let mut child_env = BTreeMap::new();
    for (key, value) in &spec.env {
        validate_env_key(key)?;
        validate_env_value(value)?;
        child_env.insert(key.clone(), value.clone());
    }
    for (key, value) in &ctx.env_allowlist {
        validate_env_key(key)?;
        validate_env_value(value)?;
        child_env.insert(key.clone(), value.clone());
    }
    ensure_secret_env_allowed(child_env.keys(), &spec.allow_secret_env)?;
    Ok(child_env)
}

pub(crate) fn validate_env_key(key: &str) -> Result<()> {
    if key.trim().is_empty() {
        return Err(Error::invalid_config("runner.env", "key must not be empty"));
    }
    if key.contains('=') {
        return Err(Error::invalid_config(
            "runner.env",
            "key must not contain '='",
        ));
    }
    if key.as_bytes().contains(&0) {
        return Err(Error::invalid_config(
            "runner.env",
            "key must not contain NUL bytes",
        ));
    }
    Ok(())
}

pub(crate) fn validate_env_value(value: &str) -> Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(Error::invalid_config(
            "runner.env",
            "value must not contain NUL bytes",
        ));
    }
    Ok(())
}

pub(crate) fn ensure_secret_env_allowed<'a, I>(keys: I, allowed: &[String]) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let allowed_set: BTreeSet<&str> = allowed.iter().map(String::as_str).collect();
    for key in keys {
        if is_secret_like(key) && !allowed_set.contains(key.as_str()) {
            return Err(Error::SecretEnvDenied { key: key.clone() });
        }
    }
    Ok(())
}

fn is_secret_like(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.ends_with("_TOKEN") || upper.ends_with("_KEY") || upper.ends_with("_SECRET")
}
