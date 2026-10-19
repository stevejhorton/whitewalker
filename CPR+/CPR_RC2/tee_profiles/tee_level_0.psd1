@{
    # RC2.1 (Required H): explicit identity markers. The active profile used to
    # be identified only by SHA256 equality with a reference file, which breaks
    # the moment the reference gains a new tag - making a genuinely stale active
    # profile indistinguishable from a custom one. Level is the operator's
    # CHOSEN volume knob and must be preserved across any refresh/repair;
    # ProfileVersion changes whenever the reference content changes, so a stale
    # active copy is detectable without guessing.
    Level          = 0
    ProfileVersion = 'RC2.1'
    # =========================================================================
    # tee_level_0.psd1 - SILENT
    # =========================================================================
    # Haystack/tee subsystem is fully wired and enabled, but NOTHING fires.
    # Use this as the safe default active profile (WW_tee_events.psd1) when
    # you want the tee mechanism present but quiet - e.g. immediately after
    # a fresh CPR install, before you've decided what you want to watch.
    #
    # Needle hits from haystack.ps1/haystack_action.ps1 are UNAFFECTED by
    # this file - this profile only controls Write-TeeLog call sites in
    # WW_main.ps1 and other CPR scripts. Needle hits are a separate,
    # independently-configured mechanism (needles.cfg).
    Events = @{}
}
