"""Template filters for the NSE elements renderer.

The recursive ``_render_elements.html`` partial needs a way to look up
a dict value by a runtime-determined key — Django's stock template
syntax can't do ``{{ row.col_key }}`` when ``col_key`` is itself a
variable. This module adds the one filter that gap requires.

Kept separate from any presentation/business logic so it stays a tiny
focused module (currently one filter); future additions belong here as
well rather than in a generic ``utils.py`` Django won't auto-discover.
"""

from django import template

register = template.Library()


@register.filter
def get_item(d, key):
    """Look up ``key`` in dict ``d``; return empty string if missing.

    Used by ``_render_elements.html`` to render list-of-homogeneous-dicts
    elements as a table: the outer loop iterates rows, the inner loop
    iterates the column keys, and this filter pulls the cell value out
    of each row.

    Returns "" (not None) for missing keys so the template renders an
    empty cell cleanly rather than the literal "None" string.
    """
    if hasattr(d, "get"):
        return d.get(key, "")
    return ""
