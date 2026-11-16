#!/bin/sh
# Hand-written fixture for Agent 1 tests. Never run.
set -e
python -m pip install --upgrade pip
pip3 install --index-url https://user:tok3n@pypi.corp.example.invalid/simple internal-tool==1.2
sudo -H pip install requests-oauthlib
npm install -D jest@29 typescript
npm i lodash@^4.17.21 my-alias@npm:left-pad@1.3.0 github:someone/repo
yarn add @scope/thing
npx create-react-app my-app
uv add httpx
conda install numpy
npm install
echo "pip install not-a-command-here"
