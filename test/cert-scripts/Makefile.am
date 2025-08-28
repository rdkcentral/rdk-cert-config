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
    cert-scripts/cert_utils.sh \
    cert-scripts/create_ca.sh \
    cert-scripts/create_leaf_cert.sh \
    cert-scripts/generate_test_rdk_certs.sh

# Run installation steps during installation
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(datadir)/cert-scripts
	chmod +x $(DESTDIR)$(datadir)/cert-scripts/*.sh
	$(MKDIR_P) $(DESTDIR)/etc/pki
	cd $(DESTDIR) && ln -sf $(datadir)/cert-scripts /etc/pki/scripts
	@echo "Certificate scripts installed successfully at $(DESTDIR)$(datadir)/cert-scripts"
	@echo "Scripts are also available at $(DESTDIR)/etc/pki/scripts"
	@echo ""
	@echo "To generate test certificates, run: $(DESTDIR)/etc/pki/scripts/generate_test_rdk_certs.sh --type <client|server> [OPTIONS]"

	# Create default OpenSSL config if it doesn't exist
	@if [ ! -f "$(DESTDIR)/etc/pki/openssl.cnf" ]; then \
		echo "Creating default OpenSSL configuration at $(DESTDIR)/etc/pki/openssl.cnf"; \
		$(DESTDIR)$(datadir)/cert-scripts/cert_utils.sh; \
	fi
