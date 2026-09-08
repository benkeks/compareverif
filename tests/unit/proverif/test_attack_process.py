from compareverif.proverif.attack_process import extract_attack_processes


def test_extracts_attack_process_from_long_trace():
    trace = """
-- Query not attacker(s[]) in process 1.
Additional knowledge of the attacker:
c
leak
pk(a)
a
1st process: out(leak, ~M) with ~M = pk(skA_2) done
1st process: out(leak, ~M_1) with ~M_1 = spk(skB_2) done
2nd process: in(c, pkX: pkey) done with message pk(a)
2nd process: out(c, ~M_3) with ~M_3 = aenc(sign(pair(spk(skB_2),k_4),skB_2),
pk(a)) done
1st process: in(c, x: bitstring) done with message aenc(adec(~M_3,a),~M) = aenc(sign(pair(spk(skB_2),k_4),skB_2),pk(skA_2))
1st process: out(c, ~M_4) with ~M_4 = senc(s,k_4) done
The attacker has the message sdec(~M_4,getsnd(getmes(adec(~M_3,a)))) = s.
"""
    source = """
free c: channel.
channel leak.
fun pk(skey): pkey.
fun spk(sskey): spkey.
fun aenc(bitstring, pkey): bitstring.
fun senc(bitstring, key): bitstring.
"""

    processes = extract_attack_processes(trace, source)

    assert len(processes) == 1
    assert processes[0].render() == """new attack_a: skey;
in(leak, attack_M: pkey);
in(leak, attack_M_1: spkey);
out(c, pk(attack_a));
in(c, attack_M_3: bitstring);
out(c, aenc(adec(attack_M_3,attack_a),attack_M));
in(c, attack_M_4: bitstring);
if sdec(attack_M_4,getsnd(getmes(adec(attack_M_3,attack_a)))) = s then event attack_breaks_query_1()"""


def test_uses_bitstring_for_conflicting_attacker_fresh_name_types():
    trace = """
-- Query not attacker(s[]) in process 1.
Additional knowledge of the attacker:
a
The attacker has the message pair(pk(a),spk(a)) = s.
"""
    source = """
fun pk(skey): pkey.
fun spk(sskey): spkey.
"""

    [process] = extract_attack_processes(trace, source)

    assert process.statements[0] == "new attack_a: bitstring;"


def test_extracts_mirrored_cost_channel_actions():
    trace = """
-- Query not attacker(secret[]) in process 1.
1st process: in(cost, hack(4)) done with message hack(4)
1st process: out(cost, ~M) with ~M = compute(2) done
The attacker has the message secret = secret.
"""

    [process] = extract_attack_processes(trace)

    assert process.statements == (
        "out(cost, hack(4));",
        "in(cost, compute(2));",
        "if secret = secret then event attack_breaks_query_1()",
    )