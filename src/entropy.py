import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    """
    Calculates the Shannon Entropy of a byte sequence.
    Returns a value between 0.0 (no randomness) and 8.0 (completely random/encrypted).
    
    Formula: H(x) = -sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0

    entropy = 0
    length = len(data)
    
    # Count frequency of each byte (0-255)
    counts = Counter(data)

    for count in counts.values():
        # Probability of this byte appearing
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy