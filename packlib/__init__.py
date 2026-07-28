"""packlib — the pack system: language x axis x tier, composed into one rule set.

    from packlib import load_policy
    P = load_policy("dealership", root="/path/to/repo")
    P.for_runtime("python")     # the packs that read a .py module
    P.inventory.report()        # what is in the tree, and what nothing can read
"""
from .loader import (PackError, Pack, ResolvedPolicy, load_policy, TIERS,  # noqa: F401
                     PACKS, PROJECTS, ORGS, ROOT)
from .detect import inventory, claim, Inventory  # noqa: F401

__all__ = ["load_policy", "PackError", "Pack", "ResolvedPolicy", "TIERS",
           "inventory", "claim", "Inventory", "PACKS", "PROJECTS", "ORGS", "ROOT"]
