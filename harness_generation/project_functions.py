"""Which project functions a harness may call, and which only describe an algorithm.

``functions.json`` is read as a set of **names** in two places -- Stage 4's
``_load_function_metadata`` and the pipeline validator's
``_target_function_names`` -- and a set of names cannot answer the question both
of them are really asking, which is whether a call to one of them would link.

Three things a name does not carry, and all three are in the miner's output
already:

*Defined or merely declared.*
    ``_extract_functions`` records prototypes as well as definitions, and
    ``_deduplicate_functions`` keeps a declaration only when no definition
    shares its signature.  A name that is declared and never defined -- a
    function this project expects to link from somewhere else -- therefore
    reaches the allow-set with nothing behind it.

*Linkage.*
    ``static uint16_t le16(const uint8_t *p)`` in ``mini_parser/target.c`` is a
    real definition with real evidence behind it, and it is still a call the
    harness cannot make: the harness is compiled as its own translation unit and
    linked against the target's objects, so the symbol is not there to resolve.

*Which definition.*
    Two files may each define a function of the same name.  Both are real; a
    call to that name still does not say which one it means.

So the question is answered once, here, as an index over the miner's rows.
:meth:`ProjectFunctionIndex.resolve` turns a name into one of five verdicts and
exactly one of them -- :data:`LINKABLE` -- authorizes a call.  The verdicts are
values, not exceptions: whether an unresolvable name is fatal depends on who
asked, and only the caller knows whether the contract *requires* the call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


#: Exactly one definition here with external linkage.  The only verdict that
#: authorizes a call from the harness.
LINKABLE = "linkable"
#: Defined here, but ``static``: the name stays inside its translation unit.
INTERNAL_LINKAGE = "internal_linkage"
#: Declared here and never defined, so there is nothing to link against.
DECLARED_ONLY = "declared_only"
#: More than one linkable definition shares the name, so a call is ambiguous.
AMBIGUOUS = "ambiguous"
#: The project does not have this name at all.
ABSENT = "absent"

#: Storage-class specifiers that hold a definition inside its translation unit.
_INTERNAL_STORAGE = frozenset({"static"})


def _storage_specifiers(value: Any, name: str) -> tuple[str, ...]:
    """A row's storage-class specifiers, or a refusal to guess at them.

    An absent ``storage`` means the miner had none to report, which is what a
    plain externally linked definition looks like.  A ``storage`` of the wrong
    shape is not that: ``"static"`` where the miner writes a list would arrive
    as *no* specifiers, and no specifiers is the one reading that authorizes a
    call.  So the wrong shape is refused instead of read.

    Guessing the other way -- call an unreadable shape internal -- would refuse
    calls that do link, which is the smaller loss; the point is not which way
    the guess errs but that neither reading is this class's to make.  Note the
    asymmetry with ``defined``, which is read with ``is True`` and therefore
    fails closed on a shape it does not recognize: a row that cannot say it is
    defined is a row that authorizes nothing.
    """

    if value is None:
        return ()
    if isinstance(value, (list, tuple)) and all(
        isinstance(item, str) for item in value
    ):
        return tuple(value)
    raise ValueError(
        f"functions.json row for {name!r} has storage {value!r}, which is not a "
        f"list of storage-class specifiers"
    )


@dataclass(frozen=True)
class ProjectFunction:
    """One ``functions.json`` row, reduced to what linkage depends on."""

    name: str
    function_id: str = ""
    defined: bool = False
    storage: tuple[str, ...] = ()
    file: str = ""
    start_line: int | None = None

    @property
    def internal_linkage(self) -> bool:
        return any(
            specifier.strip().lower() in _INTERNAL_STORAGE
            for specifier in self.storage
        )

    @property
    def linkable(self) -> bool:
        """Whether a call from another translation unit can resolve to this."""

        return self.defined and not self.internal_linkage

    def where(self) -> str:
        """Where the miner found it, for a diagnostic a reader can act on."""

        if not self.file:
            return self.function_id or "an unnamed location"
        if self.start_line is None:
            return self.file
        return f"{self.file}:{self.start_line}"


@dataclass(frozen=True)
class FunctionResolution:
    """What a name came to, and the rows that decided it."""

    name: str
    status: str
    records: tuple[ProjectFunction, ...] = ()

    @property
    def callable(self) -> bool:
        return self.status == LINKABLE

    def why(self) -> str:
        """One sentence naming the function and the reason for the verdict.

        The caller owns the error vocabulary, so this returns prose rather than
        raising: the same verdict is a refusal in one place and a recorded
        note in another.
        """

        if self.status == LINKABLE:
            return f"{self.name} is defined in {self.records[0].where()}"
        if self.status == INTERNAL_LINKAGE:
            return (
                f"{self.name} is static in {self.records[0].where()}, so a call "
                f"to it cannot be linked from the harness"
            )
        if self.status == DECLARED_ONLY:
            return (
                f"{self.name} is declared in {self.records[0].where()} but never "
                f"defined in this project, so there is nothing to link"
            )
        if self.status == AMBIGUOUS:
            locations = ", ".join(record.where() for record in self.records)
            return (
                f"{self.name} has {len(self.records)} linkable definitions "
                f"({locations}), so a call to it does not say which one"
            )
        return f"{self.name} is not a function of this project"


@dataclass(frozen=True)
class ProjectFunctionIndex:
    """Every function the miner recorded, keyed by name on demand."""

    functions: tuple[ProjectFunction, ...] = ()

    @classmethod
    def from_records(
        cls, records: Iterable[Mapping[str, Any]]
    ) -> ProjectFunctionIndex:
        """Build the index from the ``functions`` array of ``functions.json``.

        Rows that cannot be read as a named function are skipped rather than
        raising.  Both callers validate the document's shape for themselves
        before they get here -- Stage 4 with the strict version that pins the
        error text, the pipeline validator with the lenient one that treats an
        unreadable file as no functions at all -- and neither is asking this
        class to re-litigate that.

        A row's *storage* is a different matter and is not skipped past.  See
        :func:`_storage_specifiers`: the shapes that cannot be read are the ones
        that would otherwise come out looking externally linked, and a name that
        looks externally linked is a name this index authorizes a call to.
        """

        functions: list[ProjectFunction] = []
        for record in records:
            if not isinstance(record, Mapping):
                continue
            name = record.get("name")
            if not isinstance(name, str) or not name:
                continue
            start_line = record.get("start_line")
            functions.append(ProjectFunction(
                name=name,
                function_id=str(record.get("id", "") or ""),
                defined=record.get("defined") is True,
                storage=_storage_specifiers(record.get("storage"), name),
                file=str(record.get("file", "") or ""),
                start_line=(
                    start_line
                    if isinstance(start_line, int) and not isinstance(start_line, bool)
                    else None
                ),
            ))
        return cls(tuple(functions))

    @classmethod
    def from_document(cls, document: Any) -> ProjectFunctionIndex:
        """Build the index from a whole ``functions.json`` document, leniently."""

        if not isinstance(document, Mapping):
            return cls()
        records = document.get("functions")
        if not isinstance(records, list):
            return cls()
        return cls.from_records(records)

    def by_name(self, name: str) -> tuple[ProjectFunction, ...]:
        return tuple(item for item in self.functions if item.name == name)

    def resolve(self, name: str) -> FunctionResolution:
        """The verdict for one name.  Never raises: see :class:`FunctionResolution`."""

        records = self.by_name(name)
        if not records:
            return FunctionResolution(name, ABSENT)
        linkable = tuple(record for record in records if record.linkable)
        if len(linkable) > 1:
            return FunctionResolution(name, AMBIGUOUS, linkable)
        if linkable:
            return FunctionResolution(name, LINKABLE, linkable)
        defined = tuple(record for record in records if record.defined)
        if defined:
            # Defined but not linkable, and ``linkable`` is empty, so every one
            # of them is internal.
            return FunctionResolution(name, INTERNAL_LINKAGE, defined)
        return FunctionResolution(name, DECLARED_ONLY, records)

    @property
    def names(self) -> frozenset[str]:
        """Every name the project has a row for, defined or not.

        This is the set the *redefinition* rule reads: a harness that writes its
        own ``le16`` is still writing a name the project owns, and that check is
        about names, not about linkage.
        """

        return frozenset(item.name for item in self.functions)
