import re

filepath = 'packages/soroban-sas-sdk/src/client.rs'
with open(filepath, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};" in line:
        lines[i] = "use soroban_sdk::{Address, BytesN, Env, String as SorobanString};\n"
    elif "Configures the [`Env`] for this [`SASClient`]." in line:
        # the next line is empty in the original code, change it to ///
        if lines[i+1].strip() == "":
            lines[i+1] = "    ///\n"
    elif "mod test {" in line:
        lines[i] = line + "    use soroban_sdk::Bytes;\n"
    
    # fix unused envs
    # list of line numbers from clippy: 328, 472, 505, 530, 622, 658, 675, 1043, 2144, 2962, 3002, 3058, 3077, 3112, 3185, 3266, 3545, 3714, 3734
    lines_to_fix = [328, 472, 505, 530, 622, 658, 675, 1043, 2144, 2962, 3002, 3058, 3077, 3112, 3185, 3266, 3545, 3714, 3734]
    if i + 1 in lines_to_fix:
        if "let env =" in line:
            lines[i] = line.replace("let env =", "let _env =")

with open(filepath, 'w') as f:
    f.writelines(lines)

filepath_test = 'packages/soroban-sas-sdk/src/test.rs'
with open(filepath_test, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    lines_to_fix = [713, 727, 852, 871]
    if i + 1 in lines_to_fix:
        if "let env =" in line:
            lines[i] = line.replace("let env =", "let _env =")

with open(filepath_test, 'w') as f:
    f.writelines(lines)

filepath_cli = 'packages/soroban-sas-cli/src/main.rs'
with open(filepath_cli, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    lines_to_fix = [1385, 2176, 3106]
    if i + 1 in lines_to_fix:
        if "let env =" in line:
            lines[i] = line.replace("let env =", "let _env =")

with open(filepath_cli, 'w') as f:
    f.writelines(lines)

print("Fixed warnings!")
