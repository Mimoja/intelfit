rule intel_bootguard {
    strings:
        $acbp = "__ACBP__" // BootPolicyManifest
        $keym = "__KEYM__" // Key
        $ibbs = "__IBBS__" // BootBlock
        $pmda = "__PMDA__" // BootPolicyManifestVendorTag
        $pmsg = "__PMSG__" // BootPolicySignature

    condition:
        any of them
}
