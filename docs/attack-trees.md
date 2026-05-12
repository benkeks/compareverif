# Attack Tree Files

The `attack_tree_extractor.py` script produces:

1. **Summary to console** - Lists extracted clauses and derivations for each scenario
2. **Dot files** (optional) - Graphviz graph description format, loadable in any graphviz tool
3. **PDF files** (optional) - Visual diagrams of attack trees
4. **JSON files** (optional) - Plain machine-readable attack tree structure

The attack tree visualizations show:
- **Query/goal node** as a purple elliptical node at the top
- **Intermediate facts** as grey rectangular nodes
- **Table facts** (`table(...)`) as cylinder-shaped nodes
- **Channel transport facts** (`mess(...)`) as note-shaped nodes
- **Attack capabilities** as dedicated red octagonal leaf nodes with their costs (e.g., `1 hack`, `100 time`)
- **Optional clause IDs** inside fact nodes when `--show-clause-ids` is enabled
- **Optional attack highlighting** (`--highlight-attack`) that fades branches not on paths above attack capability nodes
- **OR markers on capability edges** when multiple capabilities can realize the same fact

When `--json-out` is enabled, each scenario additionally produces a JSON file
`<scenario>_derivation.json` with this structure:

- `meta`: Goal/query/rendering settings
- `nodes`: Flat node list with stable per-tree IDs and fields such as:
  - `id`, `node_type`, `fact`, `variant_id`, `rule`, `clause_number`, `clause_scope`
  - `depends_on_all`: conjunctive prerequisites (AND)
  - `depends_on_any`: disjunctive prerequisite groups (OR), represented as list-of-lists
  - `costs`: present for capability nodes, includes capability prices (e.g., `{"hack": 1}`)

Semantics example:

- `depends_on_all: [A, B]` and `depends_on_any: [[C, D]]` means:
  - `(A AND B AND (C OR D))`