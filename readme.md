## Crypto Graphy Project

This project implement tha grabled circuit based protocol for computing **GE**(a, b), $a=a_1a_0 \in {0,1}^2$, and $b=b_1b_0\in\{0,1\}^2$.

The implementation contains:

* A DES algorithm as a PRF $H:\{0,1\}^{64}\times\{0,1\}^{64}\rightarrow\{0,1\}^{64}$
* A length-doubling PRG $G:\{0,1\}^{64}\times\{0,1\}^{64}\rightarrow\{0,1\}^{128}$
* A procedure that takes a boolean circuit of **GE**(a, b) as input and outputs a grabled circuit of **GE**(a, b)
* A procedure that takes a grabled circuit of **GE**(a, b) and a set of input labels as input, evaluates the grabled circuit, and produces an output label.
