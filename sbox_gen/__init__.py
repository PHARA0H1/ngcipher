"""
S-box Generation Package

This package implements algorithms for generating cryptographically
strong S-boxes (substitution boxes) using genetic algorithms and
other optimization techniques.
"""

from .genetic_algorithm import generate_optimized_sbox, evaluate_sbox

__all__ = ['generate_optimized_sbox', 'evaluate_sbox']
