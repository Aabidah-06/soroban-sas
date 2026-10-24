import os, base64

def fix(path):
    with open(path, "r") as f:
        text = f.read()
    
    # Check if base64 encoded
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        if "use soroban" in decoded or "fn " in decoded or "#![no_std]" in decoded:
            with open(path, "w") as f:
                f.write(decoded)
            print(f"Decoded {path}")
            return
    except:
        pass

    # Apply syntax fixes
    text = text.replace("#`!no_std]", "#![no_std]")
    text = text.replace("#`!llow_unexpected_cfs])", "#![allow(unexpected_cfgs)]")
    text = text.replace("#[config(test)]mod test {", "#[cfg(test)]\nmod test {")
    text = text.replace("Address as__;", "Address as _;")
    text = text.replace("use soroban_sas_common(", "use soroban_sas_common::{")
    text = text.replace("events{", "events::{")
    text = text.replace("use soroban_sdk{", "use soroban_sdk::{")
    
    with open(path, "w") as f:
        f.write(text)

for root, dirs, files in os.walk("contracts"):
    for file in files:
        if file.endswith(".rs") or file.endswith(".md"):
            fix(os.path.join(root, file))

for root, dirs, files in os.walk("packages"):
    for file in files:
        if file.endswith(".rs"):
            fix(os.path.join(root, file))

fix("CHANGELOG.md")
fix("docs/architecture.md")

