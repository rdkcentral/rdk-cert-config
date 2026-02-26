# Copyright 2025 Comcast Cable Communications Management, LLC
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

certscriptsdir = $(datadir)/cert-scripts
certscripts_SCRIPTS = \
    cert_utils.sh \
    create_ca.sh \
    create_leaf_cert.sh \
    generate_test_rdk_certs.sh

# Distribute source files with the tarball
EXTRA_DIST = create_reference_p12.c

# Build helper programs
noinst_PROGRAMS = create_reference_p12
create_reference_p12_SOURCES = create_reference_p12.c
create_reference_p12_LDADD = $(OPENSSL_LIBS)

# Run installation steps during installation
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(datadir)/cert-scripts
	chmod +x $(DESTDIR)$(datadir)/cert-scripts/*.sh
	$(INSTALL_PROGRAM) create_reference_p12 $(DESTDIR)$(datadir)/cert-scripts/create_reference_p12
	$(MKDIR_P) $(DESTDIR)/etc/pki
	$(MKDIR_P) $(DESTDIR)/etc/ssl/certsel
	cd $(DESTDIR) && ln -sf $(datadir)/cert-scripts /etc/pki/scripts
	@echo "Certificate scripts installed successfully at $(DESTDIR)$(datadir)/cert-scripts"
	@echo "Created CertSelector configuration directory at $(DESTDIR)/etc/ssl/certsel"