# Manifest Files

For each input file, the preprocessor generates a `manifest.json` file in the corresponding scenario directory (e.g., `_scenarios/hashed_passwords/manifest.json`). This manifest provides a comprehensive machine-readable record of all generated scenarios and their verification results.

## Manifest structure

```json
{
  "input_file": "hashed_passwords.pv",
  "generated_at": null,
  "scenarios": [
    {
      "file": "base_scenario.pv",
      "path": "_scenarios/hashed_passwords/base_scenario.pv",
      "capabilities": [],
      "total_costs": {},
      "queries": [
        {
          "tag": "no faux authentication",
          "query": "(* no faux authentication *)\nquery uidx: uid;"
        }
      ],
      "verification": {
        "status": "success",
        "query_results": [
          {
            "tag": "no faux authentication",
            "result": true
          }
        ],
        "error_message": null
      }
    }
  ]
}
```

## Manifest fields

- **`input_file`**: Original ProVerif file that was processed
- **`scenarios`**: Array of all generated scenario files, each containing:
  - **`file`**: Scenario filename
  - **`path`**: Full path to the scenario file
  - **`capabilities`**: List of attacker capabilities included in this scenario:
    - `name`: Capability name (e.g., "Rainbow table attack")
    - `costs`: Cost dictionary for this capability (e.g., `{"time": 10}`)
  - **`total_costs`**: Aggregated costs across all capabilities in this scenario
  - **`queries`**: List of ProVerif security checks (`query`/`weaksecret`):
    - `tag`: Human-readable query label
    - `query`: Full ProVerif query text
  - **`verification`**: ProVerif verification results:
    - `status`: Verification status (success/error/timeout/exception)
    - `query_results`: Array of outcomes for each query (tag and true/false result)
    - `error_message`: Error details if verification failed