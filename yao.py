from Crypto.Random import get_random_bytes
import random
from des import des

# pesudorandom_func is a func H: {0, 1}^64 * {0, 1}^64 -> {0, 1}^64 DES
def PRF_H(k, x):
    encrypted_text = des(k, x)
    return encrypted_text

# We need a length doubling PRF F_k: {0, 1}^64 -> {0, 1}^128
# F_k(x) = H_k(1) || H_k(2)
def PRF_F(k, x):
    one_bin = int_to_byte(1)
    two_bin = int_to_byte(2)
    
    # F(k, x) = G(H(k, x)) = H(H(k, x), 1) || H(H(k, x), 2)
    new_k = PRF_H(k, x)
    part1 = PRF_H(new_k, one_bin)
    part2 = PRF_H(new_k, two_bin)
    out = part1 + part2
    return out

def int_to_byte(x:int):
    return x.to_bytes(8, 'big')

def bytes_xor(byte_array1, byte_array2):
    result = bytes(a ^ b for a, b in zip(byte_array1, byte_array2))
    return result

def enc(k, x):
    # Enc(k, x) = (r, s1 || s2) = (r, F_k(r) \xor (x||0^n))
    r = get_random_bytes(8)
    s1 = PRF_F(k, r)            # F_k(r)
    zero_bin = int_to_byte(0)
    s2 = x + zero_bin           # (x||0^n)
    s = bytes_xor(s1, s2)
    return (r, s)
    
def dec(k, r, s):
    # If the last n bits of F_k(r) \xor s is not 0^n output bottom
    F_k_r = PRF_F(k, r)
    result = bytes_xor(F_k_r, s)        # F_k(r) \xor s = 
    if int_to_byte(0) == result[8:]:
        # output first n bits of F_k(r) \xor s
        return result[0:8]
    else:
        return "bottom"
    
def double_enc(k_u, k_v, k_w):
    # Enc(k_u, Enc(k_v, k_w))
    r1, s1 = enc(k_v, k_w)
    s1_left, s1_right = s1[0:int(len(s1)/2)], s1[int(len(s1)/2):] 
    r2, s2 = enc(k_u, s1_left)
    return (r1, r2, s1_right, s2)

def double_dec(k_v, k_u, r1, r2, s1_right, s2):
    # Enc(k_u, Enc(k_v, k_w))
    s1_left = dec(k_u, r2, s2)
    if s1_left == "bottom":
        return "bottom"
    s1 = s1_left + s1_right
    dec_k_w = dec(k_v, r1, s1)
    return dec_k_w
    


def eval_bc(a0, a1, b0, b1):
    # We don't use wires[0], it is just a padding.
    wires = [0] * (bc["wire_num"] + 1)
    for i in bc["a0"]:
        wires[i] = a0
    for i in bc["a1"]:
        wires[i] = a1
    for i in bc["b0"]:
        wires[i] = b0
    for i in bc["b1"]:
        wires[i] = b1
    for gate in bc["gates"]:
        id = gate["id"]
        op = gate["op"]
        input = gate["in"]
        if op == "NOT":
            wires[id] = 1 - wires[input[0]]
        if op == "AND":
            wires[id] = wires[input[0]] and wires[input[1]]
        if op == "OR":
            wires[id] = wires[input[0]] or wires[input[1]]
    out = wires[bc["out"]]
    # print(out)
    return out
    
def eval_gc(input_labels, gc):
    # init wires with input labels a0, a1, b0, b1
    # the first wire (wire 0) is for padding
    wires = [0] * (gc["wire_num"] + 1)
    for i, label in enumerate(input_labels):
        wires[i] = label
    
    garbled_gates = gc["gates"]
    for gate in garbled_gates:
        if gate == {}:
            continue
        id = gate["id"] # or called out wire idx
        op = gate["op"]
        in_wires_idxs = gate["in"]
        garbled_table = gate["enc_table"]
        if op == "NOT":
            k_u = wires[in_wires_idxs[0]]
            for table_entry in garbled_table:
                r, s = table_entry
                dec_k_w = dec(k_u, r, s)
                if dec_k_w == "bottom":
                    continue
                else:
                    wires[id] = dec_k_w
        if op == "AND" or op == "OR":
            k_u = wires[in_wires_idxs[0]]
            k_v = wires[in_wires_idxs[1]]
            for table_entry in garbled_table:
                r1, r2, s1_right, s2 = table_entry
                dec_k_w = double_dec(k_v, k_u, r1, r2, s1_right, s2)
                if dec_k_w == "bottom":
                    continue
                else:
                    wires[id] = dec_k_w
                 
    out_wire = gc["out"]
    return wires[out_wire]
        
            
def generate_GC_from_BC(bc):
    wire_num = bc["wire_num"]
    GC_wires = init_wires(wire_num) # GC_wires looks like [[], [k_w_0, k_w_1], ...], the first element (wire 0) is empty for padding
    input_wire_labels = [[]] # indicate the input wires, the first element (wire 0) is empty for padding
    input_wires_idx = bc["a0"] + bc["a1"] + bc["b0"] + bc["b1"]
    input_wire_labels = GC_wires[0: len(input_wires_idx) + 1]
    
    gates = bc["gates"]
    garbled_gates = [{}]    # we don't use garbled_gates[0], it is just a padding
    for gate in gates:
        # {"id":10, "op":"AND", "in": [2,8]}, get keys from wire2 and wire8
        garbled_table = gen_garbled_table(gate, GC_wires)
        new_gate = {"id":gate["id"],
                    "op":gate["op"],
                    "in":gate["in"],
                    "enc_table": garbled_table
                    }
        garbled_gates.append(new_gate)
    gc = {
        "wire_num": 16,
        "a0": bc["a0"],
        "a1": bc["a1"],
        "b0": bc["b0"],
        "b1": bc["b1"],
        "out": bc["out"],
        "gates": garbled_gates
    }
    output = GC_wires[-1]
    return gc, input_wire_labels, output
        
# Using a list to represent wires, each wire has 2 tabels(secret keys) [k_w_0, k_w_1]
def init_wires(wire_num):
    GC_wires = [[]]     # We don't use GC_wires[0], it is just a padding
    for i in range(wire_num):
        k_w_0 = get_random_bytes(8)
        k_w_1 = get_random_bytes(8)
        GC_wires.append([k_w_0, k_w_1])
    return GC_wires

def gen_garbled_table(gate, GC_wires):
    # {"id":7, "op":"NOT", "in": [1]}, get keys from wire1
    # {"id":10, "op":"AND", "in": [2,8]}, get keys from wire2 and wire8
    # {"id":16, "op":"OR", "in": [14,15]},get keys from wire14 and wire15
    id = gate["id"]
    op = gate["op"]
    in_wires = gate["in"]
    if op == "NOT":
        inputs_u = GC_wires[in_wires[0]]
        outputs_w = GC_wires[id]
        # get wires of the gate
        k_u_0, k_u_1 = inputs_u[0], inputs_u[1]
        k_w_0, k_w_1 = outputs_w[0], outputs_w[1]
        # out = (r, s) = (r, F_k(r) \xor (x||0s))
        enc_table = [
            enc(k_u_0, k_w_1),
            enc(k_u_1, k_w_0)
        ]
        permuted_enc_table = permute_table(enc_table)
    if op == "AND":
        # in_wires = [2, 8]
        inputs_u = GC_wires[in_wires[0]]
        inputs_v = GC_wires[in_wires[1]]
        outputs_w = GC_wires[id]
        # get wires of the gate
        k_u_0, k_u_1 = inputs_u[0], inputs_u[1]
        k_v_0, k_v_1 = inputs_v[0], inputs_v[1]
        k_w_0, k_w_1 = outputs_w[0], outputs_w[1]
        
        enc_table = [
            double_enc(k_u_0, k_v_0, k_w_0),
            double_enc(k_u_0, k_v_1, k_w_0),
            double_enc(k_u_1, k_v_0, k_w_0),
            double_enc(k_u_1, k_v_1, k_w_1)
        ]
        permuted_enc_table = permute_table(enc_table)
    if op == "OR":
        # in_wires = [14, 15]
        inputs_u = GC_wires[in_wires[0]]
        inputs_v = GC_wires[in_wires[1]]
        outputs_w = GC_wires[id]
        # get wires of the gate
        k_u_0, k_u_1 = inputs_u[0], inputs_u[1]
        k_v_0, k_v_1 = inputs_v[0], inputs_v[1]
        k_w_0, k_w_1 = outputs_w[0], outputs_w[1]
        
        enc_table = [
            double_enc(k_u_0, k_v_0, k_w_0),
            double_enc(k_u_0, k_v_1, k_w_1),
            double_enc(k_u_1, k_v_0, k_w_1),
            double_enc(k_u_1, k_v_1, k_w_1)
        ]
        permuted_enc_table = permute_table(enc_table)
        
    return permuted_enc_table
            
def permute_table(enc_table):
    size = len(enc_table)
    random_idx = random.sample(range(0, size), size)
    permuted_enc_table = []
    for i in random_idx:
        permuted_enc_table.append(enc_table[i])
    return permuted_enc_table
    
def run(a0, a1, b0, b1, bc):
    # Alice:
    #   1. Alice generate GC from Boolean Circuit
    gc, input_wire_labels, out_wire_labels = generate_GC_from_BC(bc)
    #   2. Alice prepare the input wires' labels, stores in input_wire_labels
    a0_entrys = gc["a0"]
    a1_entrys = gc["a1"]
    b0_entrys = gc["b0"]
    b1_entrys = gc["b1"]
    input_labels = [0] * (len(a0_entrys + a1_entrys + b0_entrys + b1_entrys) + 1)
    #   3. Alice gives her input to input_labels
    #   4. Alice erases her candidate input in input_wire_labels
    for e in a0_entrys:
        input_labels[e] = input_wire_labels[e][a0]
        input_wire_labels[e][a0] = 0
    for e in a1_entrys:
        input_labels[e] = input_wire_labels[e][a1]
        input_wire_labels[e][a1] = 0
        
    # Bob:
    #   1. Bob receive the GC
    #   2. Bob receive the desensitized candidate input (input_wire_labels) from Alice
    #   3. Bob add his input to input_labels base on b0 & b1
    for e in b0_entrys:
        input_labels[e] = input_wire_labels[e][b0]
    for e in b1_entrys:
        input_labels[e] = input_wire_labels[e][b1]
    #   4. Bob evaluate the GC and get an output
    garbled_out_by_bob = eval_gc(input_labels, gc)
    
    # Bob Send garbled_out_wire to Alice:
    if garbled_out_by_bob == out_wire_labels[0]:
        return 0
    else:
        return 1
    

if __name__ == "__main__":
    # Use a json to represent BC
    bc = {
        "wire_num": 16,
        "a0": [6],
        "a1": [3, 4],
        "b0": [5],
        "b1": [1, 2],
        "out": 16,
        "gates":[
            {"id":7, "op":"NOT", "in": [1]},
            {"id":8, "op":"NOT", "in": [4]},
            {"id":9, "op":"NOT", "in": [6]},
            {"id":10, "op":"AND", "in": [2,8]},
            {"id":11, "op":"AND", "in": [5,9]},
            {"id":12, "op":"NOT", "in": [10]},
            {"id":13, "op":"NOT", "in": [11]},
            {"id":14, "op":"AND", "in": [3,7]},
            {"id":15, "op":"AND", "in": [12,13]},
            {"id":16, "op":"OR", "in": [14,15]}
        ]
    }
    
    for a0 in [0, 1]:
        for a1 in [0, 1]:
            for b0 in [0, 1]:
                for b1 in [0, 1]:
                    gc_out = run(a1=a1, a0=a0, b1=b1, b0=b0, bc=bc)
                    bc_out = eval_bc(a1=a1, a0=a0, b1=b1, b0=b0)
                    print(f"a1 = {a1}, a0 = {a0}, b1 = {b1}, b0 = {b0}")
                    print(f"    gc_out: {gc_out}, bc_out: {bc_out}")
    