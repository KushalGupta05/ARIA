# Working on ARIA

Use the root README to create a Python environment and build the React console. For frontend changes, run `python ML_Model/demo.py` in one terminal and `npm run dev --prefix ARIA-Frontend` in a second. Vite proxies `/api` to the local API on port 8000. [Project quickstart](README.md#try-the-console)

## Run the repository checks

From the repository root and with the virtual environment active, run

```sh
python -m pip install -r tests/requirements.txt
python tests/test_api.py -v
npm ci --prefix ARIA-Frontend
npm run build --prefix ARIA-Frontend
python -m playwright install chromium
python tests/test_browser.py -v
```

The API tests cover fresh databases, repeat seeding, technique counts, settings and case resolution. The browser test starts a temporary server, opens a synthetic case, inspects its telemetry, resolves it and reloads the page to verify persistence. On Linux, Playwright can install its system dependencies with `python -m playwright install --with-deps chromium`. [CI workflow](.github/workflows/ci.yml)

## Report a problem

Include the command or console action, the expected result and the observed result. For UI issues, identify the browser and demo case involved. Use the synthetic casebook for screenshots and reproduction steps. [Example cases](examples/cases.json)
