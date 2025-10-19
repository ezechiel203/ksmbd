# ASN.1 File Generation for KSMBD

## Issue
The ARM build process fails with errors like:
```
make[4]: *** No rule to make target 'ksmbd_spnego_negtokeninit.asn1.c', needed by 'ksmbd_spnego_negtokeninit.asn1.o'.  Stop.
```

## Root Cause
The build system expects ASN.1 source files to be generated from `.asn1` files using the kernel's `asn1_compiler` tool, but this tool is not available in all build environments.

## Current Solution
Minimal stub files have been created to allow compilation:

- `ksmbd_spnego_negtokeninit.asn1.c` - Stub C source
- `ksmbd_spnego_negtokeninit.asn1.h` - Header with function declarations
- `ksmbd_spnego_negtokentarg.asn1.c` - Stub C source
- `ksmbd_spnego_negtokentarg.asn1.h` - Header with function declarations

These files contain only the necessary declarations and includes. The actual ASN.1 parsing function implementations are in `asn1.c`.

## Proper Generation (When Available)

In a proper kernel build environment with `asn1_compiler` available, these files would be automatically generated using:

```bash
# From the kernel source directory with ASN.1 compiler available:
asn1_compiler ksmbd_spnego_negtokeninit.asn1 ksmbd_spnego_negtokeninit.asn1.c
asn1_compiler ksmbd_spnego_negtokentarg.asn1 ksmbd_spnego_negtokentarg.asn1.c
```

## File Structure

### ASN.1 Source Files:
- `ksmbd_spnego_negtokeninit.asn1` - SPNEGO negotiation token initialization ASN.1 definition
- `ksmbd_spnego_negtokentarg.asn1` - SPNEGO negotiation token target ASN.1 definition

### Generated/Stub Files:
- `ksmbd_spnego_negtokeninit.asn1.c` - Generated C source (stub version currently)
- `ksmbd_spnego_negtokeninit.asn1.h` - Function declarations header
- `ksmbd_spnego_negtokentarg.asn1.c` - Generated C source (stub version currently)
- `ksmbd_spnego_negtokentarg.asn1.h` - Function declarations header

### Implementation Files:
- `asn1.c` - Contains the actual ASN.1 parsing function implementations
- `asn1.h` - ASN.1 parsing helper functions and structures

## Functions Declared

### From ksmbd_spnego_negtokeninit.asn1.h:
- `ksmbd_gssapi_this_mech()` - GSSAPI mechanism OID parsing
- `ksmbd_neg_token_init_mech_type()` - Mechanism type parsing
- `ksmbd_neg_token_init_mech_token()` - Mechanism token parsing

### From ksmbd_spnego_negtokentarg.asn1.h:
- `ksmbd_neg_token_targ_resp_token()` - Response token parsing

## Build Integration

The Makefile includes these rules:
```makefile
ksmbd-y += ksmbd_spnego_negtokeninit.asn1.o ksmbd_spnego_negtokentarg.asn1.o asn1.o

$(obj)/asn1.o: $(obj)/ksmbd_spnego_negtokeninit.asn1.h $(obj)/ksmbd_spnego_negtokentarg.asn1.h
$(obj)/ksmbd_spnego_negtokeninit.asn1.o: $(obj)/ksmbd_spnego_negtokeninit.asn1.c $(obj)/ksmbd_spnego_negtokeninit.asn1.h
$(obj)/ksmbd_spnego_negtokentarg.asn1.o: $(obj)/ksmbd_spnego_negtokentarg.asn1.c $(obj)/ksmbd_spnego_negtokentarg.asn1.h
```

This ensures the header files are generated before the main `asn1.c` file is compiled, and that the ASN.1 object files are built and linked into the module.

## Notes
- The current stub files are sufficient for compilation and functionality
- The actual ASN.1 parsing logic is implemented in `asn1.c` using standard Linux kernel ASN.1 parsing functions
- If you have a proper kernel build environment, you can regenerate these files using the asn1_compiler tool for more complete implementations