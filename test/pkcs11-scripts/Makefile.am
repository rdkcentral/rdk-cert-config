# RDK-CERT-CONFIG-ORIGINAL-WORK
#
# Copyright (c) 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "Apache License");
# this file may be used only in accordance with that License.
# A copy of the License is available at:
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed in writing,
# the software is provided on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied.
# See the License for permissions and limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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
