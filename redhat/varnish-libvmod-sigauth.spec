%define varnish_src $HOME/varnish-3.0.3/
%define vmod_dir /usr/lib64/varnish/vmods/

Summary: varnish-libvmod-sigauth
Name: varnish-libvmod-sigauth
Version: 0.1
Release: %{build_release}
License: BSD
Group: System Environment/Daemons
Source0: ./libvmod-sigauth.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: varnish > 3.0
BuildRequires: make, autoconf, automake, libtool, python-docutils

%description
libvmod-sigauth

%prep
%setup -n libvmod-sigauth

%build
./autogen.sh
# this is a hack and assumes a prebuilt copy of varnish in VARNISHSRC.
./configure VARNISHSRC=%{varnish_src} VMODDIR=%{vmod_dir} --prefix=/usr/
make

%install
make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}/usr/share/doc/%{name}/
cp README.rst %{buildroot}/usr/share/doc/%{name}/
cp COPYING %{buildroot}/usr/share/doc/%{name}/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{vmod_dir}
%doc /usr/share/doc/%{name}/*

%{_mandir}/man3/*.3*

%preun

%changelog
* Wed Oct 03 2012 Lasse Karstensen <lasse@varnish-software.com> - 0.1-0.20120918
- Initial version.
