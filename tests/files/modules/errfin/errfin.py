from malduck import Extractor


class ErrFin(Extractor):
    family = "errfin"
    yara_rules = "ErrFin",

    @Extractor.extractor
    def boom(self, p, hit):
        raise RuntimeError("required extraction failed")

    @Extractor.final
    def finalize(self, p):
        # Must be short-circuited: error occurred during extraction,
        # so partial config can't be reported as a complete one
        return True


class OkFin(Extractor):
    family = "okfin"
    yara_rules = "OkFin",

    @Extractor.extractor
    def okfin(self, p, hit):
        return True

    @Extractor.final
    def finalize(self, p):
        return {"final": True}


class WeakFin(Extractor):
    family = "weakfin"
    yara_rules = "WeakFin",

    @Extractor.weak
    @Extractor.extractor
    def weakfin(self, p, hit):
        return {"weak": True}

    @Extractor.extractor
    def strongfin(self, p, hit):
        return True

    @Extractor.weak
    @Extractor.final
    def finalize(self, p):
        return {"final": True}
