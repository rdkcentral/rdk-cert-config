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

# Run installation steps during installation
install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(datadir)/cert-scripts
	chmod +x $(DESTDIR)$(datadir)/cert-scripts/*.sh
	$(MKDIR_P) $(DESTDIR)/etc/pki
	cd $(DESTDIR) && ln -sf $(datadir)/cert-scripts /etc/pki/scripts
	@echo "Certificate scripts installed successfully at $(DESTDIR)$(datadir)/cert-scripts"