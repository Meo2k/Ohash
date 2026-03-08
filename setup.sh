#!/usr/bin/env bash

### Install ohash for linux

cat << EOF > ~/.local/bin/ohash
#!/usr/bin/env bash
SCRIPT_DIR="$(pwd)"
export PYTHONPATH="\$SCRIPT_DIR/src:\$PYTHONPATH"
exec python3 "\$SCRIPT_DIR/ohash.py" "\$@"
EOF
chmod +x ~/.local/bin/ohash
