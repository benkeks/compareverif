#!/bin/bash

MYDOCKER() {
    docker exec compareverifRecreate "$@"
}

docker create --name compareverifRecreate -t compareverif bash
docker start compareverifRecreate
rm -rf out-hashed out-comparison out-singularization

echo "Section 2: Running example"
echo "Should end with two \`is true\` messages for the two queries of password and hashed password security."
read  -n 1 -p "Ready? [Hit any key!]" input_selection
echo "---begin of output---"
echo "[.. only showing tail of output...]"

MYDOCKER proverif -lib examples/primitives.pvl examples/hashed_passwords_paper.pv | tail -n 20

echo "---end of output---"
echo ""

echo "Section 4.1: Attack Scenario Batch Processing"
echo "Should reproduce output from paper, i.e. no pw leakage: {Server compromised} (cost: 4 hack) and {Database leak, Rainbow table attack} (cost: 1 hack, 2 time); no hashed pw leakage: {Database leak} (cost: 1 hack)"
read  -n 1 -p "Ready? [Hit any key!]" input_selection
echo "---begin of output---"

MYDOCKER python3 scenario_preprocessor.py examples/hashed_passwords_paper.pv

echo "---end of output---"
echo ""

echo "Section 4.1, end: Production of Pareto Fronts (resembling Fig. 3)"
read  -n 1 -p "Ready? (Will write files to out-hashed) [Hit any key!]" input_selection

MYDOCKER python3 pareto_comparison.py --out-png out-hashed/comparison _scenarios/hashed_passwords_paper/

echo ""

echo "Section 4.2: Attack Tree Extraction"
echo "---begin of output---"

MYDOCKER python3 attack_tree_extractor.py --graphviz-pdf out-hashed --no-summary _scenarios/hashed_passwords_paper/rainbow_table_attack+database_leak.pv

docker cp compareverifRecreate:/compareverif/out-hashed/ out-hashed/
echo "---end of output---"

read  -n 1 -p "Rendered results are in out-hashed. Hit any key when ready to continue!"

echo ""

echo "Section 5.3, Fig. 5: Bechmarking Singularization Using CompareVerif"
read  -n 1 -p "Ready? (Will write results to out-comparison) [Hit any key!]" input_selection

MYDOCKER python3 scenario_preprocessor.py examples/singularized_passwords_paper.pv
MYDOCKER python3 pareto_comparison.py --out-png out-comparison/comparison --query "no pw leakage" _scenarios/hashed_passwords_paper/ _scenarios/singularized_passwords_paper/

docker cp compareverifRecreate:/compareverif/out-comparison/ out-comparison/
read  -n 1 -p "Rendered results are in out-comparison. Hit any key when ready to continue!"

echo ""

echo "Section 5.3, Fig. 6: Attack tree for Singularization"
read  -n 1 -p "Ready? (Will write results to out-singularization) [Hit any key!]" input_selection

echo "---begin of output---"

MYDOCKER python3 attack_tree_extractor.py --no-summary --graphviz-pdf out-singularization _scenarios/singularized_passwords_paper/rainbow_table_attack+database_leak+singularization_database_leak.pv

docker cp compareverifRecreate:/compareverif/out-singularization/ out-singularization/
echo "---end of output---"

docker stop compareverifRecreate

echo "You can still inspect the docker container by running: docker start compareverifRecreate; docker exec -it compareverifRecreate bash."
echo "Otherwise remove by: docker rm compareverifRecreate"

echo "---END of Reproduction Script---"
