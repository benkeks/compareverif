#!/bin/bash

echo "Section 2: Running example"
echo "Should end with two \`is true\` messages for the two queries of password and hashed password security."
read  -n 1 -p "Ready? [Hit any key!]" input_selection
echo "---begin of output---"
echo "[.. only showing tail of output...]"

docker run compareverif proverif -lib examples/primitives.pvl examples/hashed_passwords_paper.pv | tail -n 20

echo "---end of output---"
echo ""

echo "Section 4.1: Attack Scenario Batch Processing"
echo "Should reproduce output from paper, i.e. no pw leakage: {Server compromised} (cost: 4 hack) and {Database leak, Rainbow table attack} (cost: 1 hack, 2 time); no hashed pw leakage: {Database leak} (cost: 1 hack)"
read  -n 1 -p "Ready? [Hit any key!]" input_selection
echo "---begin of output---"

docker run compareverif python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv

echo "---end of output---"
echo ""

echo "Section 4.1, end: Production of Pareto Fronts"
read  -n 1 -p "Ready? (Will open windows with the visualizations for each query.) [Hit any key!]" input_selection

docker run compareverif python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv >> /dev/null \
    && python3 pareto_comparison.py _scenarios/hashed_passwords_paper/

echo ""

echo "Section 4.2: Attack Tree Extraction"
read  -n 1 -p "Ready? (Will open windows with attack tree for pw security query on rainbow_table_attack+database_leak scenario) [Hit any key!]" input_selection
echo "---begin of output---"

docker run compareverif python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv >> /dev/null \
    && python3 attack_tree_extractor.py --no-summary _scenarios/hashed_passwords_paper/rainbow_table_attack+database_leak.pv

echo "---end of output---"
echo ""

echo "Section 5.3, Fig. 5: Bechmarking Singularization Using CompareVerif"
read  -n 1 -p "Ready? (Will open window to compare pw security query on singularized system version) [Hit any key!]" input_selection
echo "[Output in window]"

docker run compareverif python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv examples/singularized_passwords_paper.pv >> /dev/null \
    && python3 pareto_comparison.py --query "no pw leakage" _scenarios/hashed_passwords_paper/ _scenarios/singularized_passwords_paper/

echo ""

echo "Section 5.3, Fig. 6: Attack tree for Singularization"
read  -n 1 -p "Ready? (Will open windows with attack tree for pw security query on singularized system version ) [Hit any key!]" input_selection

echo "---begin of output---"

docker run compareverif python3 scenario_preprocessor.py examples/singularized_passwords_paper.pv >> /dev/null \
    && python3 attack_tree_extractor.py --no-summary  _scenarios/singularized_passwords_paper/rainbow_table_attack+database_leak+singularization_database_leak.pv

echo "---end of output---"

echo "---END of Reproduction Script---"
