"""Repair recipe registry and metadata definitions (TASK-018).

This module defines the Recipe dataclass and the in-memory recipe registry.
Recipes declare the finding codes they handle, required preconditions, and
lossiness/salvage characteristics.

Guarantees:
- Pure functions and immutable dataclasses: zero I/O, zero file writes.
- Fail-fast validation: registering an unknown precondition name raises ValueError.
- No silent overwrites: registering duplicate recipe names raises ValueError.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from sesslint.repair.preconditions import PRECONDITION_FUNCS


@dataclass(frozen=True, slots=True)
class Recipe:
    """Specification of a deterministic repair recipe."""

    name: str
    handles: tuple[str, ...]
    preconditions: tuple[str, ...]
    lossy: bool
    salvage_only: bool
    apply: Any = None
    min_policy: str = "conservative"
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Recipe name must be a non-empty string")
        # Ensure handles is sorted
        sorted_handles = tuple(sorted(self.handles))
        if sorted_handles != self.handles:
            object.__setattr__(self, "handles", sorted_handles)
        if (self.salvage_only or self.lossy) and self.min_policy == "conservative":
            object.__setattr__(self, "min_policy", "salvage")
        if self.lossy and not self.salvage_only:
            object.__setattr__(self, "salvage_only", True)


_REGISTRY: dict[str, Recipe] = {}
REGISTRY: Final[dict[str, Recipe]] = _REGISTRY


def register_recipe(recipe: Recipe) -> None:
    """Register a repair recipe with fail-fast precondition validation.

    Raises:
        ValueError: If recipe name already registered or contains unknown preconditions.
    """
    if recipe.name in _REGISTRY:
        raise ValueError(f"Duplicate recipe name: '{recipe.name}' is already registered")

    for prec in recipe.preconditions:
        if prec not in PRECONDITION_FUNCS:
            raise ValueError(f"Recipe '{recipe.name}' references unknown precondition: '{prec}'")

    _REGISTRY[recipe.name] = recipe


def get_recipe(name: str) -> Recipe | None:
    """Retrieve a registered recipe by name, or None if not found."""
    return _REGISTRY.get(name)


def recipes_for(code: str) -> tuple[Recipe, ...]:
    """Return all registered recipes handling the given finding code in registration order."""
    return tuple(r for r in _REGISTRY.values() if code in r.handles)


def list_recipes() -> tuple[Recipe, ...]:
    """Return all currently registered recipes in registration order."""
    return tuple(_REGISTRY.values())


def clear_registry() -> None:
    """Clear all registered recipes (primarily for test isolation)."""
    _REGISTRY.clear()


__all__ = [
    "REGISTRY",
    "Recipe",
    "clear_registry",
    "get_recipe",
    "list_recipes",
    "recipes_for",
    "register_recipe",
]
