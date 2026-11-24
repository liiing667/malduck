rule ErrFin
{
    strings:
        $boom = "errfin_boom"
    condition:
        $boom
}

rule OkFin
{
    strings:
        $okfin = "okfin_trigger"
    condition:
        $okfin
}

rule WeakFin
{
    strings:
        $weakfin = "weakfin_weak"
        $strongfin = "weakfin_strong"
    condition:
        any of them
}
