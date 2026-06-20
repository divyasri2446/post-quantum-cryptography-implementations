"""
quantum_rng.py
--------------
Step 1: Run a Qiskit circuit (Hadamard + measure) on IBM hardware or AerSimulator
        to produce true quantum random bits.
Step 2: Convert those bits into a seed (bytes).
Step 3: Expand that seed using HMAC-DRBG (classical CSPRNG) into as many
        random bytes as needed - no further quantum calls required.
"""

import os
import hmac
import hashlib
import struct
from dotenv import load_dotenv

load_dotenv()

# ── Track entropy source for status endpoint ──────────────────────────────────
_entropy_source = "not_initialized"
_quantum_seed: bytes | None = None
_drbg_counter = 0
_drbg_key: bytes | None = None


# ── STEP 1 & 2: Quantum seed generation ──────────────────────────────────────

def _generate_seed_from_simulator() -> bytes:
    """Fallback: use Qiskit AerSimulator (free, instant, unlimited)."""
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator

    n_qubits = 24  # stay within AerSimulator's 29 qubit limit
    n_runs = 11    # 11 runs × 24 bits = 264 bits → enough for 32 byte seed

    simulator = AerSimulator()
    raw_bits = ""

    for _ in range(n_runs):
        qc = QuantumCircuit(n_qubits, n_qubits)
        qc.h(range(n_qubits))        # Hadamard → superposition
        qc.measure(range(n_qubits), range(n_qubits))

        from qiskit import transpile
        compiled = transpile(qc, simulator)
        result = simulator.run(compiled, shots=1).result()
        counts = result.get_counts()
        bitstring = list(counts.keys())[0].replace(" ", "")
        raw_bits += bitstring

    # Convert bit string to bytes
    seed = int(raw_bits, 2).to_bytes(len(raw_bits) // 8, byteorder="big")
    return seed


def _generate_seed_from_ibm() -> bytes:
    """Primary: use real IBM Quantum hardware via the Sampler primitive."""
    from qiskit import QuantumCircuit, transpile
    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2

    token = os.getenv("IBM_QUANTUM_TOKEN")
    instance = os.getenv("IBM_QUANTUM_INSTANCE", "ibm-q/open/main")

    if not token or token == "your_token_here":
        raise ValueError("IBM_QUANTUM_TOKEN not set in .env")

    service = QiskitRuntimeService(
        channel="ibm_quantum_platform",
        token=token,
        instance=instance,
    )

    # Pick the least busy real backend
    backend = service.least_busy(operational=True, simulator=False, min_num_qubits=5)

    n_qubits = 5   # Use 5 qubits (available on all IBM open backends)
    n_shots = 512  # 512 shots × 5 qubits → 2560 bits → we hash down to 32 bytes

    qc = QuantumCircuit(n_qubits, n_qubits)
    qc.h(range(n_qubits))
    qc.measure(range(n_qubits), range(n_qubits))

    compiled = transpile(qc, backend)

    sampler = SamplerV2(mode=backend)
    job = sampler.run([compiled], shots=n_shots)
    result = job.result()

    # SamplerV2 results expose classical registers as BitArrays under .data
    pub_result = result[0]
    creg_name = compiled.cregs[0].name           # usually "c"
    bit_array = getattr(pub_result.data, creg_name)
    counts = bit_array.get_counts()

    # Concatenate all measurement outcomes → hash to fixed-size seed
    raw = "".join(k.replace(" ", "") * v for k, v in counts.items())
    seed = hashlib.sha256(raw.encode()).digest()  # 32 bytes
    return seed


def initialize_quantum_seed(force_simulator: bool = False) -> dict:
    """
    Called once at startup (or on demand via /random/seed endpoint).
    Tries real IBM hardware first, falls back to AerSimulator.
    Returns info dict for the status endpoint.
    """
    global _quantum_seed, _entropy_source, _drbg_key, _drbg_counter

    source = "unknown"
    backend_name = "AerSimulator"

    if not force_simulator:
        try:
            _quantum_seed = _generate_seed_from_ibm()
            source = "ibm_quantum_hardware"
            backend_name = "IBM Quantum Hardware"
        except Exception as e:
            print(f"[QRNG] IBM hardware unavailable ({e}), falling back to AerSimulator.")
            _quantum_seed = _generate_seed_from_simulator()
            source = "aer_simulator"
            backend_name = "AerSimulator (fallback)"
    else:
        _quantum_seed = _generate_seed_from_simulator()
        source = "aer_simulator"
        backend_name = "AerSimulator"

    _entropy_source = source
    _drbg_key = _quantum_seed   # seed the DRBG
    _drbg_counter = 0

    return {
        "source": source,
        "backend": backend_name,
        "seed_hex": _quantum_seed.hex(),
        "seed_bytes": len(_quantum_seed),
    }


# ── STEP 3: Classical CSPRNG expansion (HMAC-DRBG) ───────────────────────────

def _ensure_initialized():
    """Auto-initialize with simulator if not yet done (dev convenience)."""
    global _quantum_seed
    if _quantum_seed is None:
        print("[QRNG] Auto-initializing with AerSimulator...")
        initialize_quantum_seed(force_simulator=True)


def get_random_bytes(n: int) -> bytes:
    """
    Return n cryptographically secure random bytes,
    derived from the quantum seed via HMAC-DRBG expansion.
    No further quantum calls needed.
    """
    global _drbg_counter
    _ensure_initialized()

    output = b""
    while len(output) < n:
        # HMAC-DRBG: key=quantum_seed, msg=counter (big-endian 8 bytes)
        counter_bytes = struct.pack(">Q", _drbg_counter)
        block = hmac.new(_drbg_key, counter_bytes, hashlib.sha256).digest()
        output += block
        _drbg_counter += 1

    return output[:n]


def get_random_int(low: int, high: int) -> int:
    """Return a random integer in [low, high] inclusive."""
    span = high - low + 1
    n_bytes = (span.bit_length() + 7) // 8
    while True:
        val = int.from_bytes(get_random_bytes(n_bytes), "big")
        if val < span:
            return low + val


def get_entropy_source() -> str:
    return _entropy_source


def get_seed_hex() -> str:
    _ensure_initialized()
    return _quantum_seed.hex() if _quantum_seed else ""