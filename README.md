# stark-verifier

Original post is in [here](https://hackmd.io/5M-GRAwgROO68MhNusSDZw?both).

## Introduction

Motivation of this work was to make more fast, light prover and to reduce the verification cost using aggregation technique. Recursion & aggregation for zkSNARK proof system has been developed by several people, and shown that it has large *recursion overhead*. It requires the expensive pairing check inside the circuit, and also too many non-native field arithmetic inside the circuit. Some people have proven that the recursion & aggregation for zkSTARK is quite really fast, as zkSTARK operates on a single finite field, and does not require pairing.(instead a lot of hashing) We can make faster and lighter prover and aggregate multiple proofs cheaply with zkSTARK technology. zkSTARK has very fast proving time, it has a drawback that its proof size is too-large to be verified on-chain. This is where zkSNARK comes in. If we can prove the verification of zkSTARK proof inside zkSNARK circuit, the resulting proof will be much smaller and can be verified on-chain! It seems that we can obtain really nice proof system by combining them. Let's see more closely.

## Prerequisites

### FRI protocol

Let’s say the following function as codeword.

$$
f: D \rightarrow \mathbb{F}
$$

We want to show the codeword is close to Reed-Solomon code defined as following:

$$
RS_k[F, D] = \{p(x)|_{x \in D}:p(X) \in F[X], \;deg\; p(X) \le k-1\}
$$

We say $\rho = k/|D|$ as **rate**, or $1/\rho$ as a **blowup factor**.

Let’s say the initial domain of FRI as $L_0$, and want to show codeword $f: L_0 \rightarrow \mathbb{F}$ is close to some polynomial $p(X)$ of degree at most $k-1.$ 

$|L_0| = 2^n, k = 2^d$

Also, denote Merkle tree commitment of $f: L \rightarrow \mathbb{F}$ as $[f]$.
Honest prover will proceed to prove that the interpolation of codeword $f$, which we call $f(X)$ has degree at most $k-1$.

FRI protocol has two phases: *commit phase* and *query phase*.

In **commit phase**, prover splits the domain size and the polynomial into half in each layer, and sends commitments of the polynomials in each layer.

![](https://i.imgur.com/8KlJmRb.png)

Each domain $L_0, L_1, \dots$ are cyclic multiplicative subgroups of $\mathbb{F}^*$.

1. Prover sends $[f_0]$ to verifier.
2. Verifier samples random field value $\beta_0$
3. Prover splits the polynomial as follows:
    $$f_0(X) = f_{0, E}(X^2) + X \cdot f_{0, O}(X^2)$$
    and computes $f_1(X)$
    $$f_1(X) = f_{0, E}(X) + \beta_0 \cdot f_{0, O}(X)$$
    Note that $f_1(X)$ has half degree of the degree of $f_0(X)$, and is defined above $L_1 = \{x^2| x \in L_0 \}$ . $L_1$ size is half of the size of $L_0$ .
    
4. Prover recursively proceeds this for $\log(k)$ rounds.
5. Prover sends this constant to verifier.

In **query** phase, verifier should check that the prover folded the polynomial correctly. This is called consistency check.

![](https://i.imgur.com/2v90WNQ.png)

1. Verifier queries random point $v, -v$ in $L_0$, and calculates the correct folded value as follows:
    
    $$f_0(v) = f_{0, E}(v^2) + v \cdot f_{0, O}(v^2) \\ f_0(-v) = f_{0, E}(v^2) - v \cdot f_{0, O}(v^2)$$
    
    From queried value $f_0(v), f_0(-v)$, verifier can obtain $f_{0, E}(v^2), f_{0, O}(v^2)$ and calculate $f_1(v^2)$ .
    
    $$f_1(v^2) = f_{0, E}(v^2) + \beta_0 \cdot f_{0, O}(v^2)$$
    
2. Verifier queries point $v^2$ in $L_1$, and checks the above equation holds.
3. Verifier checks consistencies between subsequent layers.

Verifier repeats the query phase until it reaches the desired security level.

### Cost model of FRI

It's quite important to have bird's-eye view on the cost model of FRI, because the cost is affected by the parameters of FRI.
- Prover time
For prover, the most dominant cost is to evaluate the polynomial over initial domain. It is the cost of FFT over initial domain. If rate parameter $\rho$ gets smaller, the prover time will increase.

$$O(|L_0|\log(|L_0|)) = O(\rho^{-1} \cdot k\log(\rho^{-1} \cdot k))$$

- Proof length
In query phase, prover should provide **merkle path** to decommit the evaluation on the queried point. This is the dominant cost for proof length. To achieve $\lambda$ bits of security, the verifier should repeat query phase at least $\lambda / \log(\rho^{-1})$ times. If we do many queries, then the proof length and verification cost will be bigger.

We can configure the parameters for FRI to take achieve desirable property between proving time and proof size.

### DEEP FRI
So, how can we use FRI as polynomial commitment scheme? I will re-ask the question. How can verifier query the point **outside** of the initial evaluation domain?

Let’s assume the following case:

$$f: L_0 \rightarrow \mathbb{F}, r \in \mathbb{F} \backslash L_0$$

How can verifier verifies the opening at $f(r)$? Prover and verifier can simply proceed FRI on the quotient polynomial:

$$
q(X) = {{f(X) - v} \over {X - r}}, \\
q : L_0 \rightarrow \mathbb{F}
$$

If $q(X)$ has the degree at most $k-2$, then the verifier can accept the opening. [VP19] Prover should also send $f(x)$ to check the consistency between $q(x)$ and $f(x)$ (along with merkle proof) in every query round. Prover should also send $f(x)$ to check the consistency between $q(x)$ and $f(x)$ (along with merkle proof) in every query round.

### Optimizations

There are some several techniques to reduce the proving time and the proof length of FRI. We will not deal with these techniques more deeply in this post, check out [here](https://oil-moustache-ffb.notion.site/FRI-workshop-b491d29bc6b846aaac451f206f23c012).

## Architecture

### STARK & SNARK proof composition

As first proving system we use a STARK and our main idea of composition is to delegate the verification procedure of the STARK proof $\pi_{STARK}$ to a verification circuit $C$. In this case, if the prover provides a proof for the correct execution of the verification circuit $\pi_{circuit}$, then this is enough to verify the original STARK. In this case, the verifier entity just verifies the proof of the STARK verification circuit $\pi_{circuit}$. The advantage of this composition is that $\pi_{circuit}$ is smaller and faster to verify than $\pi_{STARK}$.

### Aggregation

We used aggregation method to combine the original STARK proofs. Aggregation is a particular type of proof composition in which multiple valid proofs can be proven to be valid by comprising them all into one proof, called the *aggregated proof*, by validating only the aggregated one. In the architecture, aggregators are defined in intermediate circuits. Below describes how aggregation works:

![](https://i.imgur.com/vWXotQM.png)

We should be able to aggregate the arbitrary number of proofs, so we make tree-like structure to aggregate all of them into one. We call this *aggregation tree*.
Below describes how aggregation tree works.

![](https://i.imgur.com/olANx6K.png)

In aggregation tree, we have three different parts, or phases. First, individual provers generate STARK proofs circuits. In this part, we do not need to care about aggregation.
The remaining two phases are: aggregation phase and finalization phase.
In aggregation phase, every adjacent proofs in aggregation tree are combined into one proof by the aggregators which are defined as the circuit that encodes STARK verification logic. Let's call this aggregator as *recursive STARK prover*. When the final proof is generated at the end, this proof should be verified inside SNARK circuit. The main purpose of the finalization phase is to compress the proof and make it verifiable on-chain(e.g. EVM).

In aggregation phase, all the independent computations in each aggregation layer can be parallelized. 

![](https://i.imgur.com/mJ8V5jH.png)

Let's look more deeply into the details of each phases.

### Detail in each phase

Let's look at the each layer of the phases.
In aggregation phase, the base layer of the aggregation tree can be described as follows:

![](https://i.imgur.com/pk4iyx3.png)

Users provide witness and public inputs for circuits, and the circuits generate STARK proof. This STARK proof should be verified inside the next layer's recursive STARK prover. Thus the recursive STARK prover should be witnessed by proofs, verification key of the previous layer's circuit, and the public inputs of the previous layer's circuits. In the above figure, recursive STARK prover generates new proof that attests to the correctness of $proof0$ and $proof1$. Recursive STARK prover should pass combined public inputs and the verification key of *its own circuit* to the next layer along with the proof.



## Applications

### Semaphore for large-scaled voting

How about using Semaphore protocol for very large-scaled voting(e.g. nationwide presidential election)? Every voter should generate their proof in a short time. Also if we can aggregate all the proofs into one, we can make the gas fee charged on each voter negligible. Also, for voting case, the time spent for all the proofs to be finalized does not matter.(it would be much faster to get finalized than in the real-world voting)

I tested this aggregation scheme with Semaphore proofs, and the following is the benchmark result.

## Benchmarks

The code can be found [here](https://github.com/DoHoonKim8/stark-verifier).

### Without aggregation

Proving time measured for group size $2^{20}$ on M1 mac pro is approximately 0.95s.

FRI parameter setting is as follows:
- $\rho = 2^{-3}$ (blowup factor 8)
- 28 query rounds
- proof of work bits: 16 bits

We can see the proving time has decreased compared to current Semaphore protocol, which takes approximately [2.4s](https://benchmarks.semaphore.appliedzkp.org/) for group size $2^{20}$.

### Aggregation

Following is the benchmark result for aggregating Semaphore proofs & finalizing. Measured gas cost is the cost for verifying only Halo2 proofs, without sending public inputs of Semaphore to on-chain.(this definitely should be done later)
It was measured on r5.4xlarge ec2 instance.

|number of proofs|aggregation time|Halo2 proving time|circuit size|gas|
|---|---|---|---|---|
|2|11s|505s|k=23|407142|
|4|29s|507s|k=23|405109|
|8|64s|511s|k=23|401021|
|16|128s|509s|k=23|407388|
|32|235s|509s|k=23|406783|
|64|468s|511s|k=23|409911|
|128|930s|510s|k=23|406226|

Plonky2 library seems to be 2 times faster on M1 mac pro than on r5.4xlarge ec2 instance. (Aggregation time is much faster than on M1 mac pro) We can reduce the aggregation time more by changing machine stack and also by applying optimization techniques.

## Further works

- I hope my work can be generalized to be the framework for zkSTARK aggregation. In Semaphore, we can test completely another model other than using Merkle tree. Instead of using merkle tree, devs can use lookup arguments(e.g. [Caulk+](https://github.com/geometryresearch/semacaulk/tree/main)), and whenever they want to aggregate membership proofs and verify them on-chain, I hope they can build Plonky2 circuit that verifies pairing and aggregate them using this POC.


