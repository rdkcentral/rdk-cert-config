# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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
