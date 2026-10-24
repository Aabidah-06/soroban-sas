# 1. permissive-resolver
with open("contracts/permissive-resolver/src/lib.rs", "r") as f:
    text = f.read()
text = text.replace("#`!no_std]", "#![no_std]")
text = text.replace("#[config(test)]mod test {", "#[cfg(test)]\nmod test {")
text = text.replace("Address as__;", "Address as _;")
with open("contracts/permissive-resolver/src/lib.rs", "w") as f:
    f.write(text)

# 2. sas events.rs
with open("contracts/sas/src/events.rs", "r") as f:
    text = f.read()
text = text.replace("use soroban_sas_common(", "use soroban_sas_common::{")
with open("contracts/sas/src/events.rs", "w") as f:
    f.write(text)

# 3. common lib.rs
# It is base64 encoded, let's decode it
import base64
with open("packages/soroban-sas-common/src/lib.rs", "r") as f:
    text = f.read()
decoded = base64.b64decode(text).decode('utf-8')
with open("packages/soroban-sas-common/src/lib.rs", "w") as f:
    f.write(decoded)

