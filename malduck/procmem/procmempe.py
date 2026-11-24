from typing import List, Optional

from ..bits import align
from ..pe import PE, PELayout
from .binmem import ProcessMemoryBinary
from .procmem import ProcessMemoryBuffer
from .region import Region

__all__ = ["ProcessMemoryPE", "procmempe"]


class ProcessMemoryPE(ProcessMemoryBinary):
    """
    Representation of memory-mapped PE file

    Short name: `procmempe`

    :param buf: A memory object containing the PE to be loaded
    :type buf: bytes, mmap, memoryview, bytearray or :py:meth:`MemoryBuffer` object

    :param base: Virtual address of the region of interest (or beginning of buf when no regions provided)
    :type base: int, optional (default: 0)

    :param image: The memory object is a dump of memory-mapped PE
    :type image: bool, optional (default: False)

    :param detect_image: Try to automatically detect if the input buffer is memory-mapped PE using some heuristics
    :type detect_image: bool, optional (default: False)

    File `memory_dump` contains a 64bit memory-aligned PE dumped from address `0x140000000`, in order to load it
    into procmempe and access the `pe` field all we have to do is initialize a new object with the file data:

    .. code-block:: python

        from malduck import procmempe

        with open("memory_dump", "rb") as f:
            data = f.read()

        pe_dump = procmempe(buf=data, base=0x140000000, image=True)
        print(pe_dump.pe.is64bit)


    PE files can also be read directly using inherited :py:meth:`ProcessMemory.from_file` with `image` argument set
    (look at :py:meth:`from_memory` method).

    .. code-block:: python

        pe_dump = procmempe.from_file("140000000_1d5bdc3dbe71a7bd", image=True)
        print(pe_dump.pe.sections)
    """

    __magic__ = b"MZ"

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        self._pe: Optional[PE] = None
        super(ProcessMemoryPE, self).__init__(
            buf, base=base, regions=regions, image=image, detect_image=detect_image
        )

    def _pe_direct_load(self, fast_load: bool = True) -> PE:
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise ValueError("imgbase out of regions")
        # Expected m type: bytearray
        m = bytearray(self.readp(offset))
        pe = PE(data=m, fast_load=fast_load)
        return pe

    def _reload_as_image(self) -> None:
        # Load PE data from imgbase offset
        try:
            pe = self._pe_direct_load(fast_load=True)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(
                "Inconsistent PE layout: unable to parse PE headers"
            ) from exc
        # Validate the file layout before touching the current object.  The
        # resulting regions, the section table and store() must all describe
        # the same file.
        layout = PELayout(pe.pe, data_len=len(pe.data), validate_raw=True)
        # If mmap: close all descriptors or
        # nullify references if mmap is not owned by current object
        self.close()
        # Set memory to the pe.data buffer
        self.memory = bytearray(pe.data)
        self.imgbase = layout.image_base
        # Reset regions
        self.regions = [Region(self.imgbase, layout.headers_size, 0, 0, 0, 0)]
        # Load image sections
        for section in layout.sections:
            if section.raw_size > 0:
                self.regions.append(
                    Region(
                        self.imgbase + section.virtual_address,
                        section.raw_size,
                        0,
                        0,
                        0,
                        section.raw_offset,
                    )
                )

    def is_valid(self) -> bool:
        if self.readv(self.imgbase, 2) != self.__magic__:
            return False
        pe_offs = self.uint32v(self.imgbase + 0x3C)
        if pe_offs is None:
            return False
        if self.readv(self.imgbase + pe_offs, 2) != b"PE":
            return False
        try:
            PE(self)
            return True
        except Exception:
            return False

    def is_image_loaded_as_memdump(self) -> bool:
        """
        Checks whether memory region contains image incorrectly loaded as memory-mapped PE dump (image=False).

        .. code-block:: python

           embed_pe = procmempe.from_memory(mem)
           if not embed_pe.is_image_loaded_as_memdump():
               # Memory contains plain PE file - need to load it first
               embed_pe = procmempe.from_memory(mem, image=True)
        """
        pe = self._pe_direct_load(fast_load=True)
        # If import table is corrupted - possible dump
        if not pe.validate_import_names():
            return False
        # If resources are corrupted - possible dump
        if not pe.validate_resources():
            return False
        # If first 4kB seem to be zero-padded - possible dump
        if not pe.validate_padding():
            return False
        # No errors, so it must be PE file
        return True

    @property
    def pe(self) -> PE:
        """Related :class:`PE` object"""
        if self._pe is None:
            self._pe = PE(self)
        return self._pe

    @property
    def imgend(self) -> int:
        """Address where PE image ends"""
        section = self.pe.sections[-1]
        return self.imgbase + section.VirtualAddress + section.Misc_VirtualSize

    def store(self) -> bytes:
        """
        Store ProcessMemoryPE contents as PE file data.

        :rtype: bytes
        """
        if self.is_image:
            # image=True keeps the original file bytes in memory and maps
            # sections using their original raw offsets.  Returning that
            # buffer preserves the exact layout instead of re-laying sections
            # out according to sizes that may not match the header.
            return bytes(self.memory)
        return self._store_from_dump()

    def _load_header_pe(self) -> PE:
        """Read and parse PE headers using the object's virtual mapping."""
        offset = self.v2p(self.imgbase)
        if offset is None:
            raise ValueError("imgbase out of regions")
        if offset + 0x40 > len(self.m):
            raise ValueError("Inconsistent PE layout: truncated DOS header")
        if self.readp(offset, 2) != self.__magic__:
            raise ValueError("Inconsistent PE layout: missing MZ magic")

        pe_lfanew = self.uint32p(offset + 0x3C)
        if pe_lfanew is None or pe_lfanew < 0x40:
            raise ValueError("Inconsistent PE layout: invalid e_lfanew")
        file_header_offset = offset + pe_lfanew + 4
        if file_header_offset + 20 > len(self.m):
            raise ValueError("Inconsistent PE layout: truncated file header")
        if self.readp(offset + pe_lfanew, 4) != b"PE\x00\x00":
            raise ValueError("Inconsistent PE layout: missing PE signature")

        number_of_sections = self.uint16p(file_header_offset + 2)
        optional_header_size = self.uint16p(file_header_offset + 16)
        if number_of_sections is None or optional_header_size is None:
            raise ValueError("Inconsistent PE layout: truncated file header")
        section_table_end = (
            pe_lfanew + 24 + optional_header_size + 40 * number_of_sections
        )
        header_data = self.readv(self.imgbase, section_table_end)
        if len(header_data) < section_table_end:
            raise ValueError("Inconsistent PE layout: truncated section table")

        try:
            pe = PE(data=bytearray(header_data), fast_load=True)
        except Exception as exc:
            raise ValueError(
                "Inconsistent PE layout: unable to parse PE headers"
            ) from exc
        headers_size = max(
            section_table_end,
            int(getattr(pe.optional_header, "SizeOfHeaders", 0) or 0),
        )
        if headers_size > len(header_data):
            header_data = self.readv(self.imgbase, headers_size)
            if len(header_data) < headers_size:
                raise ValueError("Inconsistent PE layout: headers extend past input")
            try:
                pe = PE(data=bytearray(header_data), fast_load=True)
            except Exception as exc:
                raise ValueError(
                    "Inconsistent PE layout: unable to parse PE headers"
                ) from exc
        return pe

    def _store_from_dump(self) -> bytes:
        data = []
        # Read headers without trusting PointerToRawData from the (possibly
        # damaged) section table.
        pe = self._load_header_pe()
        layout = PELayout(pe.pe, data_len=len(pe.data), validate_raw=False)
        current_offs = layout.headers_size

        if (
            not 0 <= self.imgbase < layout.address_limit
            or self.imgbase % 0x10000
        ):
            raise ValueError("Cannot store PE: invalid ImageBase")
        if layout.sections:
            image_end = layout.sections[-1].virtual_end
            if self.imgbase + image_end > layout.address_limit:
                raise ValueError(
                    "Cannot store PE: ImageBase plus section addresses "
                    "overflow the address space"
                )

        for idx, section in enumerate(pe.sections):
            section_layout = layout.sections[idx]
            section_va = self.imgbase + section_layout.virtual_address
            if section_va >= layout.address_limit:
                raise ValueError(
                    f"Cannot store section {idx} ({section_layout.name!r}): "
                    "virtual address out of range"
                )
            # A section without raw data is BSS.  It has no file content and
            # must stay that way even if the dump has mapped zero pages for it.
            if section_layout.is_bss:
                continue

            # Find corresponding region
            section_region = self.addr_region(section_va)
            if not section_region:
                raise ValueError(
                    f"Cannot store section {idx} ({section_layout.name!r}): "
                    "section is not mapped in memory"
                )
            # The whole raw payload must be available.  A short read would
            # otherwise be zero-filled and silently change the section.
            if self.v2p(section_va, section_layout.raw_size) is None:
                raise ValueError(
                    f"Cannot store section {idx} ({section_layout.name!r}): "
                    "section raw data is not fully mapped in memory"
                )

            # Get possible section size
            section_size = max(section_layout.virtual_size, section_layout.raw_size)
            # Align to section alignment (usually 0x1000)
            section_alignment = max(0x1000, pe.optional_header.SectionAlignment)
            section_size = align(section_size, section_alignment)
            # Sometimes real region size is less than virtual size (image=True)
            section_size = min(
                section_region.end - section_va, section_size
            )
            # Align to file alignment (usually 0x200)
            file_alignment = max(0x200, pe.optional_header.FileAlignment)
            section_size = align(section_size, file_alignment)
            # Read section data including appropriate padding
            section_data = self.readv(section_va, section_size)
            section_data += (section_size - len(section_data)) * b"\x00"
            data.append(section_data)
            # Fix section values
            section.PointerToRawData, section.SizeOfRawData = current_offs, section_size
            current_offs += section_size

        pe.optional_header.ImageBase = self.imgbase
        pe.optional_header.SizeOfHeaders = layout.headers_size

        # Generate header data
        pe_data = b"".join([bytes(pe.pe.write())] + data)

        # Return PE file data
        return pe_data


procmempe = ProcessMemoryPE
