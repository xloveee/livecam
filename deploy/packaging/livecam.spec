Name:           livecam
Version:        0.1.0
Release:        1%{?dist}
Summary:        WebRTC livestream SFU and Go proxy
License:        AGPLv3
URL:            https://github.com/xloveee/livecam
BuildArch:      x86_64
Requires:       ca-certificates, curl
# Caddy is recommended, not required — PROXY=nginx is supported.
# Recommends is ignored on older rpm; listed for Fedora.

%description
Prebuilt rust-core + go-proxy for x86_64 Linux.
After install: sudo livecam-setup your.domain you@email.com
Secrets (SESSION_SECRET, SFU_INTERNAL_SECRET) are generated on first
setup and reused on upgrade.

%prep
# binary package; staged by build-rpm.sh

%install
install -d %{buildroot}/opt/livecam
cp -a %{_sourcedir}/opt/livecam/. %{buildroot}/opt/livecam/
install -D -m 755 %{_sourcedir}/usr/bin/livecam-setup %{buildroot}/usr/bin/livecam-setup

%files
%dir /opt/livecam
/opt/livecam/*
/usr/bin/livecam-setup

%post
if [ $1 -eq 1 ]; then
  echo "livecam: run sudo livecam-setup your.domain you@email.com"
fi

%preun
if [ $1 -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop go-proxy >/dev/null 2>&1 || :
  systemctl stop sfu >/dev/null 2>&1 || :
fi
