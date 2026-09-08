package keymgmt

// sanitizeLabel strips control characters (bytes below 0x20 and DEL 0x7f)
// from a stored key label before it is rendered in the UI. Labels are
// store-controlled strings (enrollment autolabels like
// "enrolled <RFC3339> via login@", plus arbitrary admin labels), so they
// must never smuggle terminal control sequences into a transcript. All
// remaining bytes, including UTF-8, pass through unchanged.
func sanitizeLabel(label string) string {
	clean := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		b := label[i]
		if b < 0x20 || b == 0x7f {
			continue
		}
		clean = append(clean, b)
	}
	return string(clean)
}
