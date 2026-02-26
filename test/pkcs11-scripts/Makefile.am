# Copyright 2026 RDK Management
# SPDX-License-Identifier: Apache-2.0
#

# Install PKCS#11 setup scripts
pkcs11scriptsdir = $(datadir)/pkcs11-scripts
pkcs11scripts_SCRIPTS = \
    setup-pkcs11.sh \
    setup-pkcs11-openssl.sh

# Install SoftHSM2 configuration file
pkcs11scripts_DATA = softhsm2.conf

# Make scripts executable after installation
install-data-hook:
	chmod +x $(DESTDIR)$(pkcs11scriptsdir)/*.sh
