"""Data models for attack trees and derivations."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class TreeNode:
    """Represents a node in a derivation tree."""

    fact: str
    rule: Optional[str] = None
    node_id: Optional[str] = None
    capabilities: Set[str] = field(
        default_factory=set
    )  # Capabilities that introduce this node
    clause_number: Optional[int] = None  # Clause number if derived from a clause
    clause_scope: Optional[int] = None  # Query-scope identifier for the clause number
    variant_id: Optional[str] = None  # Variant identifier for disjunctive alternatives

    def __post_init__(self):
        if self.node_id is None:
            # Generate unique ID based on fact content and variant
            variant_suffix = f"_{self.variant_id}" if self.variant_id else ""
            self.node_id = f"node_{abs(hash(self.fact + variant_suffix)) % 100000}"

    @staticmethod
    def to_readable_format(fact: str) -> str:
        """Convert ProVerif fact to readable HTML format with monospace terms.

        Returns HTML with ProVerif terms in monospace font.
        Examples:
            attacker(the_password[]) -> Attacker learns <FONT FACE="courier">the_password</FONT>.
            attacker((a, b)) -> Attacker learns <FONT FACE="courier">a</FONT> and <FONT FACE="courier">b</FONT>.
            table(passwd(a, b)) -> Table <FONT FACE="courier">passwd</FONT> contains (<FONT FACE="courier">a,b</FONT>).
        """

        def mono(text: str) -> str:
            """Wrap text in monospace HTML font."""
            return f'<FONT FACE="courier">{text}</FONT>'

        def split_on_comma_respecting_parens(text: str) -> list:
            """Split text on commas, but only at depth 0 (outside all parentheses)."""
            parts = []
            current = []
            depth = 0
            for char in text:
                if char == "(":
                    depth += 1
                    current.append(char)
                elif char == ")":
                    depth -= 1
                    current.append(char)
                elif char == "," and depth == 0:
                    parts.append("".join(current).strip())
                    current = []
                else:
                    current.append(char)
            if current:
                parts.append("".join(current).strip())
            return parts

        # Handle attacker(...) pattern
        attacker_match = re.match(r"attacker\((.+)\)\s*$", fact, re.DOTALL)
        if attacker_match:
            content = attacker_match.group(1).strip()
            # Remove [] from variable names
            content = content.replace("[]", "")

            # Check for tuple: attacker((a, b, ...))
            tuple_match = re.match(r"\((.+)\)$", content, re.DOTALL)
            if tuple_match:
                # Extract tuple elements
                elements = tuple_match.group(1)
                # Split respecting nested parentheses
                parts = split_on_comma_respecting_parens(elements)
                if len(parts) > 1:
                    items = " and ".join([mono(p) for p in parts])
                    return f"Attacker learns {items}."

            # Single value
            return f"Attacker learns {mono(content)}."

        # Handle table(NAME(args)) pattern
        table_match = re.match(r"table\((\w+)\((.*)\)\)\s*$", fact, re.DOTALL)
        if table_match:
            table_name = table_match.group(1)
            args = table_match.group(2)
            # Remove [] from variable names
            args = args.replace("[]", "")
            return f"Table {mono(table_name)} contains ({mono(args)})."

        # Handle mess(chan, msg) pattern
        mess_match = re.match(r"mess\((.+),\s*(.+)\)\s*$", fact, re.DOTALL)
        if mess_match:
            chan = mess_match.group(1).strip()
            msg = mess_match.group(2).strip()
            # Remove [] from variable names
            chan = chan.replace("[]", "")
            msg = msg.replace("[]", "")
            return f"Channel {mono(chan)} transports {mono(msg)}."

        # Handle event(e) pattern
        event_match = re.match(r"event\((.+)\)\s*$", fact, re.DOTALL)
        if event_match:
            event_content = event_match.group(1).strip()
            # Remove [] from variable names
            event_content = event_content.replace("[]", "")
            return f"Event {mono(event_content)} happens."

        # Default: return as-is (with [] removed, in monospace)
        return mono(fact.replace("[]", ""))


class DerivationTree:
    """Represents a derivation as a DAG (directed acyclic graph)."""

    def __init__(
        self,
        goal: str,
        query_tag: Optional[str] = None,
        capability_costs: Optional[Dict[str, Dict[str, int]]] = None,
        readable_nodes: bool = False,
        show_clause_ids: bool = False,
    ):
        self.goal = goal
        self.query_tag = query_tag  # Tag/name of the violated query
        self.capability_costs = capability_costs or {}  # Map: capability name -> {"time": X, "hack": Y, ...}
        self.readable_nodes = readable_nodes  # Whether to use readable node labels
        self.show_clause_ids = show_clause_ids  # Whether to display clause numbers in node labels
        self.nodes: Dict[Tuple[str, Optional[str]], TreeNode] = {}  # Key: (fact, variant_id)
        self.edges: List[Tuple[Tuple[str, Optional[str]], Tuple[str, Optional[str]], Optional[str]]] = []  # (source, target, rule)
        self.add_node(goal, "goal")

    def add_node(
        self,
        fact: str,
        rule: Optional[str] = None,
        capabilities: Optional[Set[str]] = None,
        clause_number: Optional[int] = None,
        variant_id: Optional[str] = None,
        clause_scope: Optional[int] = None,
    ) -> TreeNode:
        """Add a node to the graph if not already present."""
        key = (fact, variant_id)
        if key not in self.nodes:
            node = TreeNode(
                fact=fact,
                rule=rule,
                capabilities=capabilities or set(),
                clause_number=clause_number,
                clause_scope=clause_scope,
                variant_id=variant_id,
            )
            self.nodes[key] = node
        else:
            # Merge capabilities if node already exists
            if capabilities:
                self.nodes[key].capabilities.update(capabilities)
            # Update rule if the new rule is more specific/informative
            # Rule priority (highest to lowest): goal > clause > initial > duplicate > apply*
            rule_priority = {
                "goal": 5,
                "clause": 4,
                "initial": 3,
                "duplicate": 2,
            }
            current_priority = rule_priority.get(self.nodes[key].rule, 0)
            new_priority = rule_priority.get(rule, 0) if rule else 0
            # Also check if rule contains "apply"
            if self.nodes[key].rule and "apply" in self.nodes[key].rule:
                current_priority = 1
            if rule and "apply" in rule:
                new_priority = 1

            if new_priority > current_priority:
                self.nodes[key].rule = rule
            # Update clause number if provided
            if clause_number is not None:
                self.nodes[key].clause_number = clause_number
            if clause_scope is not None:
                self.nodes[key].clause_scope = clause_scope
        return self.nodes[key]

    def add_edge(
        self,
        source_fact: str,
        target_fact: str,
        rule: Optional[str] = None,
        capabilities: Optional[Set[str]] = None,
        clause_number: Optional[int] = None,
        source_variant: Optional[str] = None,
        target_variant: Optional[str] = None,
        clause_scope: Optional[int] = None,
    ) -> None:
        """Add an edge from source to target."""
        self.add_node(source_fact, variant_id=source_variant)
        self.add_node(
            target_fact,
            rule,
            capabilities,
            clause_number,
            variant_id=target_variant,
            clause_scope=clause_scope,
        )
        self.edges.append(
            ((source_fact, source_variant), (target_fact, target_variant), rule)
        )

    def to_graphviz(self) -> str:
        """Generate graphviz dot format representation."""
        dot_lines = ["digraph DerivationTree {"]
        dot_lines.append("  rankdir=TD;")  # Top-down layout
        dot_lines.append("  node [shape=box, style=rounded];")

        # Add all nodes
        for (fact, variant_id), node in self.nodes.items():
            # Convert to readable format if requested
            if self.readable_nodes:
                label = TreeNode.to_readable_format(fact)
            else:
                label = fact

            # For readable mode (HTML labels), break text before converting
            # For non-readable mode, break the plain text
            label_lines = [label]

            if self.readable_nodes and len(label) > 50:
                # Break HTML-formatted text at logical points before rendering
                # Find positions to break by looking at the plain text content
                text_only = re.sub(r"<[^>]+>", "", label)

                if len(text_only) > 50:
                    # Find good break points in the plain text
                    break_positions = []

                    # Look for natural break points: "). " or " and "
                    for pattern in [r"\)\.\s+", r"\sand\s+"]:
                        for match in re.finditer(pattern, text_only):
                            break_positions.append(match.end())

                    if break_positions:
                        # Sort and limit to creating 3 breaks (4 lines max)
                        break_positions.sort()
                        break_positions = break_positions[:3]

                        # Now apply these breaks to the HTML text by finding matching positions
                        # This is tricky because the HTML has tags, so we need to map positions
                        label_lines = []
                        last_html_idx = 0
                        last_text_idx = 0

                        for break_text_idx in break_positions:
                            if len(label_lines) >= 3:  # Max 4 lines
                                break

                            # Find the corresponding position in the HTML string
                            # Count characters in HTML, skipping tags
                            char_count = 0
                            html_idx = last_html_idx
                            while html_idx < len(label) and char_count < break_text_idx - last_text_idx:
                                if label[html_idx] == "<":
                                    # Skip this tag
                                    end_tag = label.find(">", html_idx)
                                    if end_tag != -1:
                                        html_idx = end_tag + 1
                                    else:
                                        html_idx += 1
                                else:
                                    char_count += 1
                                    html_idx += 1

                            # Add this line (from last_html_idx to html_idx)
                            line = label[last_html_idx:html_idx].rstrip(" ")
                            if line:
                                label_lines.append(line)

                            last_html_idx = html_idx
                            last_text_idx = break_text_idx

                        # Add remaining text
                        if last_html_idx < len(label):
                            remaining = label[last_html_idx:]
                            if remaining.strip():
                                label_lines.append(remaining)

            # Build HTML label from lines
            html_parts = []
            for line in label_lines[:4]:  # Max 4 lines
                html_parts.append(self._format_label_html(line))

            # Add query tag to goal node
            if node.rule == "goal" and self.query_tag:
                tag_html = self._format_label_html(f"(❌ {self.query_tag})")
                html_parts.append(tag_html)

            # Add clause id if enabled
            if self.show_clause_ids and node.clause_number is not None:
                clause_html = self._format_label_html(f"Clause {node.clause_number}")
                html_parts.append(clause_html)

            # Add capability annotations in bold
            if node.capabilities:
                cap_str = ", ".join(sorted(node.capabilities))
                # Use bold instead of brackets
                html_parts.append(f"<B>{cap_str}</B>")

            # Join with line breaks
            label_html = "<BR/>".join(html_parts)

            # Choose color based on rule and capabilities
            fillcolor = None
            if node.capabilities:
                # All nodes with capabilities get the same color
                fillcolor = "#DDA0DD"  # Plum
            elif node.rule == "goal":
                fillcolor = "lightgreen"
            elif node.rule and "apply" in node.rule:
                fillcolor = "lightyellow"
            elif node.rule and "clause" in node.rule:
                fillcolor = "lightblue"

            if fillcolor:
                dot_lines.append(
                    f'  {node.node_id} [label=<{label_html}>, fillcolor="{fillcolor}", style="rounded,filled"];'
                )
            else:
                dot_lines.append(f'  {node.node_id} [label=<{label_html}>];')

        # Add edges
        visited = set()
        for source_key, target_key, rule in self.edges:
            source_node = self.nodes[source_key]
            target_node = self.nodes[target_key]
            edge_key = f"{source_node.node_id}-{target_node.node_id}"

            if edge_key not in visited:
                visited.add(edge_key)
                # Check if target has multiple variants (disjunctive)
                target_fact = target_key[0]
                variants = [
                    k for k in self.nodes.keys() if k[0] == target_fact and k[1] is not None
                ]
                is_disjunctive = len(variants) > 1 and target_key[1] is not None

                # Generate edge label based on capabilities and costs
                label = ""
                cost_label = ""

                # Calculate costs from target node capabilities
                if target_node.capabilities:
                    cost_parts = []
                    for cap in sorted(target_node.capabilities):
                        if cap in self.capability_costs:
                            costs = self.capability_costs[cap]
                            for cost_type, cost_value in sorted(costs.items()):
                                cost_parts.append(f"{cost_value} {cost_type}")
                    if cost_parts:
                        cost_label = " + ".join(cost_parts)

                if is_disjunctive:
                    # For disjunctive edges, show costs and OR
                    if cost_label:
                        label = f' [label="{cost_label} (OR)", style=dashed]'
                    else:
                        label = ' [label="OR", style=dashed]'
                elif cost_label:
                    label = f' [label="{cost_label}"]'
                # If no capabilities or costs, leave edge blank (no label)

                dot_lines.append(
                    f"  {source_node.node_id} -> {target_node.node_id}{label};"
                )

        dot_lines.append("}")
        return "\n".join(dot_lines)

    @staticmethod
    def _format_label_html(text: str) -> str:
        """Escape HTML special characters in text.

        Text from to_readable_format() already contains HTML font tags,
        so we only escape unescaped ampersands and angle brackets.
        """
        # Replace & with &amp; (but not &amp; or &lt; or &gt; or &nbsp; etc.)
        text = re.sub(r"&(?![a-z]+;)", "&amp;", text)

        # For now, just return as-is since to_readable_format() output is safe
        return text
