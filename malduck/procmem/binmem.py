import logging
from abc import ABCMeta, abstractmethod
from typing import Iterator, List, Optional, Type, TypeVar

from typing_extensions import Self

from .procmem import ProcessMemory, ProcessMemoryBuffer
from .region import Region

log = logging.getLogger(__name__)

T = TypeVar("T", bound="ProcessMemoryBinary")


class ProcessMemoryBinary(ProcessMemory, metaclass=ABCMeta):
    """
    Abstract class for memory-mapped executable binary
    """

    __magic__: Optional[bytes] = None

    def __init__(
        self,
        buf: ProcessMemoryBuffer,
        base: int = 0,
        regions: Optional[List[Region]] = None,
        image: bool = False,
        detect_image: bool = False,
    ) -> None:
        super().__init__(buf, base=base, regions=regions)
        if detect_image:
            image = self.is_image_loaded_as_memdump()
        self.is_image = image
        self._image: Optional[Self] = None
        if image:
            self._reload_as_image()

    @abstractmethod
    def _reload_as_image(self) -> None:
        """
        Load executable file embedded in ProcessMemory like native loader does
        """
        raise NotImplementedError()

    @property
    def image(self) -> Optional[Self]:
        """
        Returns ProcessMemory object loaded with image=True or None if can't be loaded or is loaded as image yet
        """
        if self.is_image:
            return None
        try:
            if not self._image:
                self._image = self.from_memory(self, image=True)
            return self._image
        except Exception:
            import traceback

            log.debug(
                "image construction raised an exception: %s", traceback.format_exc()
            )
            return None

    @abstractmethod
    def is_valid(self) -> bool:
        """
        Checks whether imgbase is pointing at valid binary header
        """
        raise NotImplementedError()

    @classmethod
    def load_binaries_from_memory(
        cls: Type[T], procmem: ProcessMemory, limit: Optional[int] = None
    ) -> Iterator[T]:
        """
        Looks for binaries in ProcessMemory object and yields specialized ProcessMemoryBinary objects
        :param procmem: ProcessMemory object to search
        :param limit: Maximum number of binaries (counting both memory-dump
            and loader-image mappings) yielded from this ProcessMemory.
            Remaining magic signatures are not even looked at, so fake MZ/ELF
            headers can't force an unbounded number of full binary loads.
            ``None`` means no limit.

        .. versionchanged:: 4.4.0

            In addition to image=False binaries, it also returns image=True versions.
            In previous versions it was done by extractor, so it was working only
            if memory-aligned version was also "valid".

        .. versionchanged:: 4.5.0

            Added ``limit`` parameter bounding the carving budget.
        """
        if cls.__magic__ is None:
            raise NotImplementedError()
        if limit is not None and limit <= 0:
            return
        yielded = 0
        for binary_va in procmem.findv(cls.__magic__):
            if limit is not None and yielded >= limit:
                log.warning(
                    "Reached the limit of %d carved %s binaries, "
                    "remaining candidates are skipped",
                    limit,
                    cls.__name__,
                )
                break
            binary_procmem_dmp = cls.from_memory(procmem, base=binary_va)
            if binary_procmem_dmp.is_valid():
                yield binary_procmem_dmp
                yielded += 1
                if limit is not None and yielded >= limit:
                    break
            binary_procmem_img = binary_procmem_dmp.image
            if binary_procmem_img and binary_procmem_img.is_valid():
                yield binary_procmem_img
                yielded += 1
                if limit is not None and yielded >= limit:
                    break

    @abstractmethod
    def is_image_loaded_as_memdump(self) -> bool:
        """
        Uses some heuristics to deduce whether contents can be loaded with `image=True`.
        Used by `detect_image`
        """
        raise NotImplementedError()

    def __repr__(self):
        return f"{self.__class__.__name__}:{'IMG' if self.is_image else 'DMP'}:{hex(self.imgbase)[2:]}"
