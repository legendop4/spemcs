"""Autogenerate filters, kept out of ``env.py`` so they can be imported and tested.

``env.py`` runs migrations as a side effect of being imported and only works inside an alembic run
context (``alembic.context.config`` does not exist otherwise), so a test cannot import it to check
its filters. Anything in there is therefore unverifiable by construction. This filter is a
data-loss guard on a database holding real exam history, so it lives here instead and
``tests/test_migrations.py`` exercises the same function alembic uses.
"""

from __future__ import annotations

from sqlalchemy import MetaData

__all__ = ["make_include_name"]


def make_include_name(target_metadata: MetaData):
    """Build alembic's ``include_name`` hook, excluding anything the models do not declare.

    The deployed database has drifted away from the models in a direction autogenerate handles
    badly: it contains three tables the models do not define (``buildings``, ``settings``,
    ``spemcs_users``) and nine columns on ``events`` that the model does not define. Autogenerate
    reads "in the database, not in the metadata" as "delete it", so an unfiltered
    ``revision --autogenerate`` proposes dropping all of them - including nine columns of a table
    with thousands of rows - and a reviewer who trusts the generated file ships it.

    Excluding a name removes it from the comparison altogether, which is stronger than reviewing
    the output: there is nothing to overlook.

    The trade-off is that *intentional* drops are suppressed too - removing a model no longer
    generates a ``drop_table``. That is the right way round here. An intentional drop is rare and
    can be written by hand; an accidental one is silent and irreversible.
    """

    def include_name(name, type_, parent_names) -> bool:
        if type_ == "table":
            # `name is None` denotes the default schema itself, which must stay included.
            return name is None or name in target_metadata.tables

        if type_ == "column":
            table = target_metadata.tables.get(parent_names.get("table_name"))
            if table is None:
                # A column of a table already excluded above; excluding it keeps the comparison
                # self-consistent.
                return False
            return name in table.columns

        # Schemas, indexes and unique constraints are compared normally.
        return True

    return include_name
