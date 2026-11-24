# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from typing import TYPE_CHECKING, Any, Iterator, List, Optional, Tuple, Union

import pefile

from .bits import align

if TYPE_CHECKING:
    from .procmem import ProcessMemory

__all__ = ["pe", "PE", "MemoryPEData", "PELayout", "PESectionLayout"]


class PESectionLayout:
    """Validated layout of a single PE section."""

    def __init__(
        self,
        index: int,
        name: bytes,
        virtual_address: int,
        virtual_size: int,
        raw_offset: int,
        raw_size: int,
        virtual_extent: int,
    ) -> None:
        self.index = index
        self.name = name
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.raw_offset = raw_offset
        self.raw_size = raw_size
        self.virtual_extent = virtual_extent

    @property
    def is_bss(self) -> bool:
        """Section without any bytes in the file."""
        return self.raw_size == 0

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.virtual_extent


class PELayout:
    """
    Canonical PE file layout shared by the headers, section table, memory
    regions and the result of :meth:`ProcessMemoryPE.store`.

    The layout is rejected if the section table does not describe a file that
    can be represented consistently.  In particular:

    * headers must contain the complete section table,
    * section raw data must start after the headers and stay inside the input,
    * raw ranges must not overlap,
    * virtual addresses must be aligned, sorted and non-overlapping,
    * image base and image size must not overflow the PE address space.

    ``validate_raw`` is used when the provided PE data are actual file bytes.
    Memory dumps may contain a stale ``PointerToRawData`` (or raw size) in the
    header while the section content is still available at its RVA, so the
    dump-based fixup path only validates the virtual geometry.
    """

    def __init__(
        self,
        pe: Any,
        data_len: Optional[int] = None,
        validate_raw: bool = False,
    ) -> None:
        optional_header = getattr(pe, "OPTIONAL_HEADER", None)
        file_header = getattr(pe, "FILE_HEADER", None)
        sections = getattr(pe, "sections", None)
        if optional_header is None or file_header is None or sections is None:
            raise ValueError("Inconsistent PE layout: incomplete header")

        self.pe = pe
        self.data_len = data_len
        self.validate_raw = validate_raw
        self.image_base = int(getattr(optional_header, "ImageBase", 0) or 0)
        self.section_alignment = int(
            getattr(optional_header, "SectionAlignment", 0) or 0
        )
        self.file_alignment = int(getattr(optional_header, "FileAlignment", 0) or 0)
        if (
            self.section_alignment <= 0
            or self.section_alignment & (self.section_alignment - 1)
            or self.file_alignment <= 0
            or self.file_alignment & (self.file_alignment - 1)
            or self.section_alignment < self.file_alignment
        ):
            raise ValueError("Inconsistent PE layout: invalid section alignment")
        self.size_of_image = int(getattr(optional_header, "SizeOfImage", 0) or 0)

        magic = int(getattr(optional_header, "Magic", 0) or 0)
        if magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
            address_limit = 1 << 32
        elif magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            address_limit = 1 << 64
        else:
            raise ValueError("Inconsistent PE layout: unknown optional header magic")
        self.address_limit = address_limit

        try:
            optional_offset = int(optional_header.get_file_offset())
        except (AttributeError, TypeError):
            optional_offset = int(getattr(pe.DOS_HEADER, "e_lfanew", 0)) + 24
        optional_size = int(getattr(file_header, "SizeOfOptionalHeader", 0) or 0)
        number_of_sections = int(
            getattr(file_header, "NumberOfSections", len(sections)) or 0
        )
        if number_of_sections != len(sections):
            raise ValueError(
                "Inconsistent PE layout: section table is truncated"
            )
        self.section_table_offset = optional_offset + optional_size
        self.section_table_end = self.section_table_offset + 40 * number_of_sections

        declared_headers_size = int(
            getattr(optional_header, "SizeOfHeaders", 0) or 0
        )
        if declared_headers_size < self.section_table_end:
            raise ValueError(
                "Inconsistent PE layout: SizeOfHeaders does not contain "
                "the section table"
            )
        self.headers_size = declared_headers_size
        if data_len is not None and self.headers_size > data_len:
            raise ValueError("Inconsistent PE layout: headers extend past input")

        if self.image_base % 0x10000:
            raise ValueError("Inconsistent PE layout: ImageBase is not 64k aligned")
        if self.image_base >= address_limit:
            raise ValueError("Inconsistent PE layout: ImageBase out of range")
        if (
            self.size_of_image
            and self.image_base + self.size_of_image > address_limit
        ):
            raise ValueError(
                "Inconsistent PE layout: ImageBase plus SizeOfImage overflows "
                "the address space"
            )

        aligned_headers_end = align(self.headers_size, self.section_alignment)
        self.sections: List[PESectionLayout] = []
        previous_va = None
        previous_va_end = None
        raw_ranges: List[Tuple[int, int]] = []

        for index, section in enumerate(sections):
            name = bytes(getattr(section, "Name", b""))
            virtual_address = int(getattr(section, "VirtualAddress", 0) or 0)
            virtual_size = int(getattr(section, "Misc_VirtualSize", 0) or 0)
            raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
            raw_offset = int(getattr(section, "PointerToRawData", 0) or 0)
            extent = (
                align(max(virtual_size, raw_size), self.section_alignment)
                if max(virtual_size, raw_size)
                else 0
            )
            if (
                self.size_of_image
                and virtual_address + virtual_size > self.size_of_image
            ):
                raise ValueError(
                    f"Inconsistent PE layout: section {index} ({name!r}) "
                    "extends past SizeOfImage"
                )

            if extent:
                if virtual_address < aligned_headers_end:
                    raise ValueError(
                        f"Inconsistent PE layout: section {index} ({name!r}) "
                        "starts inside PE headers"
                    )
                if virtual_address % self.section_alignment:
                    raise ValueError(
                        f"Inconsistent PE layout: section {index} ({name!r}) "
                        "is not section-aligned"
                    )
            if previous_va is not None and virtual_address < previous_va:
                raise ValueError(
                    f"Inconsistent PE layout: section {index} ({name!r}) "
                    "has unsorted virtual address"
                )
            if previous_va_end is not None and virtual_address < previous_va_end:
                raise ValueError(
                    f"Inconsistent PE layout: section {index} ({name!r}) "
                    "overlaps previous section in memory"
                )

            if raw_size:
                if raw_offset < self.headers_size:
                    raise ValueError(
                        f"Inconsistent PE layout: section {index} ({name!r}) "
                        "raw data starts inside PE headers"
                    )
                if validate_raw:
                    if raw_offset % self.file_alignment:
                        raise ValueError(
                            f"Inconsistent PE layout: section {index} ({name!r}) "
                            "raw offset is not file-aligned"
                        )
                    if data_len is None or raw_size > data_len - raw_offset:
                        raise ValueError(
                            f"Inconsistent PE layout: section {index} ({name!r}) "
                            "raw data extends past input"
                        )
                    raw_ranges.append((raw_offset, raw_offset + raw_size))

            self.sections.append(
                PESectionLayout(
                    index=index,
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    virtual_extent=extent,
                )
            )
            previous_va = virtual_address
            previous_va_end = virtual_address + extent

        if validate_raw and raw_ranges:
            raw_ranges.sort()
            for (_, previous_end), (raw_start, _) in zip(
                raw_ranges, raw_ranges[1:]
            ):
                if raw_start < previous_end:
                    raise ValueError(
                        "Inconsistent PE layout: section raw ranges overlap"
                    )

        if self.sections:
            image_end = self.sections[-1].virtual_end
        else:
            image_end = aligned_headers_end
        if self.image_base + image_end > address_limit:
            raise ValueError(
                "Inconsistent PE layout: section addresses overflow the "
                "address space"
            )


class MemoryPEData:
    """
    `pefile.PE.__data__` represents image file usually aligned to 512 bytes.
    MemoryPEData perform mapping from pefile's offset-access to Memory object va-access
    based on section layout.
    """

    def __init__(self, memory: "ProcessMemory", fast_load: bool) -> None:
        self.memory = memory
        # Preload headers
        self.pe = pefile.PE(data=self, fast_load=True)
        # Perform full_load if needed
        if not fast_load:
            self.pe.full_load()

    def map_offset(self, offs: int) -> int:
        if not hasattr(self, "pe") or not self.pe.sections:
            return self.memory.imgbase + offs
        return self.memory.imgbase + (self.pe.get_rva_from_offset(offs) or offs)

    def __len__(self) -> int:
        return (
            self.memory.regions[-1].addr
            - self.memory.regions[0].addr
            + self.memory.regions[-1].size
        )

    def __getitem__(self, item: Any) -> object:
        if isinstance(item, slice):
            start = self.map_offset(item.start or 0)
            stop = self.map_offset(item.stop - 1)
        else:
            start = self.map_offset(item)
            stop = start
        return self.memory.readv(start, stop - start + 1)

    def find(self, str: bytes, beg: int = 0, end: Optional[int] = None) -> int:
        if end and beg >= end:
            return -1
        try:
            return next(
                self.memory.regexv(str, self.memory.imgbase + beg, end and end - beg)
            )
        except StopIteration:
            return -1


class PE(object):
    """
    Wrapper around :class:`pefile.PE`, accepts either bytes (raw file contents) or
    :class:`ProcessMemory` instance.
    """

    def __init__(
        self, data: Union["ProcessMemory", bytes], fast_load: bool = False
    ) -> None:
        from .procmem import ProcessMemory

        if isinstance(data, ProcessMemory):
            self.pe = MemoryPEData(data, fast_load).pe
        else:
            self.pe = pefile.PE(data=data, fast_load=fast_load)

    @property
    def data(self) -> bytes:
        return self.pe.__data__

    @property
    def dos_header(self) -> Any:
        """Dos header"""
        return self.pe.DOS_HEADER

    @property
    def nt_headers(self) -> Any:
        """NT headers"""
        return self.pe.NT_HEADERS

    @property
    def file_header(self) -> Any:
        """File header"""
        return self.pe.FILE_HEADER

    @property
    def optional_header(self) -> Any:
        """Optional header"""
        return self.pe.OPTIONAL_HEADER

    @property
    def sections(self) -> list:
        """Sections"""
        return self.pe.sections

    @property
    def is32bit(self) -> Any:
        """
        Is it 32-bit file (PE)?
        """
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE

    @property
    def is64bit(self) -> Any:
        """
        Is it 64-bit file (PE+)?
        """
        return self.optional_header.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

    @property
    def headers_size(self) -> int:
        """
        Size of the PE headers as described by the file layout.

        This is not blindly derived from the first section offset: the
        ``SizeOfHeaders`` field and the end of the section table are also
        taken into account.  If there are no sections: returns 0x1000 or size
        of input if provided data are shorter than single page.
        """
        if not self.sections:
            return min(len(self.pe.__data__), 0x1000)
        optional_header = self.optional_header
        declared_headers = int(getattr(optional_header, "SizeOfHeaders", 0) or 0)
        try:
            optional_offset = int(optional_header.get_file_offset())
        except (AttributeError, TypeError):
            optional_offset = int(self.dos_header.e_lfanew) + 24
        table_end = (
            optional_offset
            + int(getattr(self.file_header, "SizeOfOptionalHeader", 0) or 0)
            + 40
            * int(
                getattr(self.file_header, "NumberOfSections", len(self.sections))
                or len(self.sections)
            )
        )
        headers_size = max(declared_headers, table_end)
        first_raw = int(getattr(self.sections[0], "PointerToRawData", 0) or 0)
        if 0 < first_raw <= len(self.pe.__data__):
            headers_size = max(headers_size, first_raw)
        return headers_size

    def section(self, name: Union[str, bytes]) -> Any:
        """
        Get section by name

        :param name: Section name
        :type name: str or bytes
        """
        if isinstance(name, str):
            name = name.encode()

        for section in self.pe.sections:
            if section.Name.rstrip(b"\x00") == name:
                return section

    def directory(self, name: str) -> Any:
        """
        Get pefile directory entry by identifier

        :param name: shortened pefile directory entry identifier (e.g. 'IMPORT' for 'IMAGE_DIRECTORY_ENTRY_IMPORT')
        :rtype: :class:`pefile.Structure`
        """
        return self.optional_header.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_" + name)
        ]

    def structure(self, rva: int, format: Any) -> Any:
        """
        Get internal pefile Structure from specified rva

        :param rva: Relative virtual address of structure
        :param format: :class:`pefile.Structure` format
                       (e.g. :py:attr:`pefile.PE.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__`)
        :rtype: :class:`pefile.Structure`
        """
        structure = pefile.Structure(format)
        structure.__unpack__(self.pe.get_data(rva, structure.sizeof()))
        return structure

    def validate_import_names(self) -> bool:
        """
        Returns True if the first 8 imported library entries have valid library names
        """
        import_dir = self.directory("IMPORT")
        if not import_dir.VirtualAddress:
            # There's nothing wrong with no imports
            return True
        try:
            import_rva = import_dir.VirtualAddress
            # Don't go further than 8 entries
            for _ in range(8):
                import_desc = self.structure(
                    import_rva, pefile.PE.__IMAGE_IMPORT_DESCRIPTOR_format__
                )
                if import_desc.all_zeroes():
                    # End of import-table
                    break
                import_dllname = self.pe.get_string_at_rva(
                    import_desc.Name, pefile.MAX_DLL_LENGTH
                )
                if not pefile.is_valid_dos_filename(import_dllname):
                    # Invalid import filename found
                    return False
                import_rva += import_desc.sizeof()
            return True
        except pefile.PEFormatError:
            return False

    def validate_resources(self) -> bool:
        """
        Returns True if first level of resource tree looks consistent
        """
        resource_dir = self.directory("RESOURCE")
        if not resource_dir.VirtualAddress:
            # There's nothing wrong with no resources
            return True
        try:
            resource_rva = resource_dir.VirtualAddress
            resource_desc = self.structure(
                resource_rva, pefile.PE.__IMAGE_RESOURCE_DIRECTORY_format__
            )
            resource_no = (
                resource_desc.NumberOfNamedEntries + resource_desc.NumberOfIdEntries
            )
            if not 0 <= resource_no < 128:
                # Incorrect resource number
                return False
            for rsrc_idx in range(resource_no):
                resource_entry_desc = self.structure(
                    resource_rva + resource_desc.sizeof() + rsrc_idx * 8,
                    pefile.PE.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
                )
                if (
                    self.pe.get_word_at_rva(
                        resource_rva + resource_entry_desc.OffsetToData & 0x7FFFFFFF
                    )
                    is None
                ):
                    return False
            return True
        except pefile.PEFormatError:
            return False

    def validate_padding(self) -> bool:
        """
        Returns True if area between first non-bss section and first 4kB doesn't have only null-bytes
        """
        section_start_offs = None
        for section in self.sections:
            if section.SizeOfRawData > 0:
                section_start_offs = section.PointerToRawData
                break
        if section_start_offs is None:
            # No non-bss sections? Is it real PE file?
            return False
        if section_start_offs > 0x1000:
            # Unusual - try checking last 512 bytes
            section_start_offs = 0x800
        try:
            data_len = 0x1000 - section_start_offs
            if not data_len:
                # Probably fixpe'd - seems to be ok
                return True
            return not all(
                b in [0, "\0"]
                for b in self.pe.__data__[
                    section_start_offs : section_start_offs + data_len
                ]
            )
        except pefile.PEFormatError:
            return False

    def iterate_resources(
        self,
    ) -> Iterator[
        Tuple[
            pefile.ResourceDirEntryData,
            pefile.ResourceDirEntryData,
            pefile.ResourceDirEntryData,
        ]
    ]:
        for e1 in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for e2 in e1.directory.entries:
                for e3 in e2.directory.entries:
                    yield (e1, e2, e3)

    def resources(self, name: Union[int, str, bytes]) -> Iterator[bytes]:
        """
        Finds resource objects by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: Iterator[bytes]
        """

        def name_str(e1, e2, e3):
            return (e1.name and e1.name.string == name) or (
                e2.name and e2.name.string == name
            )

        def name_int(e1, e2, e3):
            return e2.struct.Name == name

        def type_int(e1, e2, e3):
            return e1.id == type_id

        # Broken PE files will not have this directory and it's better to return no value
        # than to throw a meaningless exception
        if not hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            return

        if isinstance(name, str):
            name = name.encode()

        if isinstance(name, bytes):
            if name.startswith(b"RT_"):
                compare = type_int
                type_id = pefile.RESOURCE_TYPE[name.decode()]
            else:
                compare = name_str
        else:
            compare = name_int

        for e1, e2, e3 in self.iterate_resources():
            if compare(e1, e2, e3):
                yield self.pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)

    def resource(self, name: Union[int, str, bytes]) -> Optional[bytes]:
        """
        Retrieves single resource by specified name or type

        :param name: String name (e2) or type (e1), numeric identifier name (e2) or RT_* type (e1)
        :type name: int or str or bytes
        :rtype: bytes or None
        """
        try:
            return next(self.resources(name))
        except StopIteration:
            return None


pe = PE
