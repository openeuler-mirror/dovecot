%global __provides_exclude_from %{_docdir}
%global __requires_exclude_from %{_docdir}
%global ssldir %{_sysconfdir}/pki/%{name}
%global restart_flag /var/run/%{name}/%{name}-restart-after-rpm-install
%global _hardened_build 1

Name:          dovecot
Version:       2.3.10.1
Release:       1
Summary:       Dovecot Secure imap server
License:       MIT and LGPLv2
URL:           http://www.dovecot.org/
Epoch:         1

Source:        http://www.dovecot.org/releases/2.3/%{name}-%{version}%{?prever}.tar.gz
Source2:       dovecot.pam
%global        pigeonholever 0.5.10
Source8:       http://pigeonhole.dovecot.org/releases/2.3/dovecot-2.3-pigeonhole-%{pigeonholever}.tar.gz
Source9:       dovecot.sysconfig
Source10:      dovecot.tmpfilesd

Patch6000:     CVE-2015-3420.patch
Patch6001:     CVE-2016-8652.patch
Patch6002:     dovecot-2.0-defaultconfig.patch
Patch6003:     dovecot-1.0.beta2-mkcert-permissions.patch
Patch6004:     dovecot-1.0.rc7-mkcert-paths.patch

#wait for network
Patch6005:     dovecot-2.1.10-waitonline.patch

Patch6006:     dovecot-2.2.20-initbysystemd.patch
Patch6007:     dovecot-2.2.22-systemd_w_protectsystem.patch

BuildRequires: gcc-c++ openssl-devel pam-devel zlib-devel bzip2-devel libcap-devel
BuildRequires: libtool autoconf automake pkgconfig sqlite-devel libpq-devel
BuildRequires: mariadb-connector-c-devel libxcrypt-devel openldap-devel krb5-devel
BuildRequires: quota-devel xz-devel gettext-devel clucene-core-devel libcurl-devel expat-devel

Requires: openssl >= 0.9.7f-4 systemd
Requires(pre): shadow-utils
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units

Provides:     %{name}-pigeonhole = 1:%{version}-%{release} %{name}-pgsql = 1:%{version}-%{release}
Obsoletes:    %{name}-pigeonhole < 1:%{version}-%{release} %{name}-pgsql < 1:%{version}-%{release}
Provides:     %{name}-mysql = 1:%{version}-%{release}
Obsoletes:    %{name}-mysql < 1:%{version}-%{release}

%description
Dovecot is an IMAP server for Linux/UNIX-like systemsa wrapper package
that will just handle common things for all versioned dovecot packages.

%package devel
Requires: %{name} = %{epoch}:%{version}-%{release}
Summary: Development files for dovecot
%description devel
This package provides the development files for dovecot.

%package  help
Summary:  Help documentation for %{name}

%description  help
Man pages and other related help documents for %{name}.


%prep
%autosetup -n %{name}-%{version}%{?prever} -a 8 -p1

sed -i '/DEFAULT_INCLUDES *=/s|$| '"$(pkg-config --cflags libclucene-core)|" src/plugins/fts-lucene/Makefile.in

%build
export CFLAGS="%{__global_cflags} -fno-strict-aliasing -fstack-reuse=none" LDFLAGS="-Wl,-z,now -Wl,-z,relro %{?__global_ldflags}"

mkdir -p m4
autoreconf -I . -fiv #required for aarch64 support

%configure  INSTALL_DATA="install -c -p -m644" \
            --docdir=%{_docdir}/%{name} --disable-static --disable-rpath --with-nss                   \
            --with-shadow --with-pam --with-gssapi=plugin --with-ldap=plugin --with-sql=plugin --with-pgsql --with-mysql  \
            --with-sqlite --with-zlib --with-libcap --with-lucene --with-ssl=openssl --with-ssldir=%{ssldir}      \
            --with-solr --with-systemdsystemunitdir=%{_unitdir} --with-docs

sed -i 's|/etc/ssl|/etc/pki/dovecot|' doc/mkcert.sh doc/example-config/conf.d/10-ssl.conf

%make_build

cd dovecot-2*3-pigeonhole-%{pigeonholever}

[ -f configure ] || autoreconf -fiv
[ -f ChangeLog ] || echo "Pigeonhole ChangeLog is not available, yet" >ChangeLog

%configure                             \
    INSTALL_DATA="install -c -p -m644" --disable-static --with-dovecot=../ --without-unfinished-features

%make_build
cd -

%install
%make_install
mv $RPM_BUILD_ROOT/%{_docdir}/%{name} %{_builddir}/%{name}-%{version}%{?prever}/docinstall

cd dovecot-2*3-pigeonhole-%{pigeonholever}
%make_install

mv $RPM_BUILD_ROOT/%{_docdir}/%{name} $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole

install -m 644 AUTHORS ChangeLog COPYING COPYING.LGPL INSTALL NEWS README $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole
cd -

install -p -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/dovecot

install -d $RPM_BUILD_ROOT%{ssldir}/certs
install -d $RPM_BUILD_ROOT%{ssldir}/private
touch $RPM_BUILD_ROOT%{ssldir}/certs/dovecot.pem
chmod 600 $RPM_BUILD_ROOT%{ssldir}/certs/dovecot.pem
touch $RPM_BUILD_ROOT%{ssldir}/private/dovecot.pem
chmod 600 $RPM_BUILD_ROOT%{ssldir}/private/dovecot.pem


install -p -D -m 644 %{SOURCE10} $RPM_BUILD_ROOT%{_tmpfilesdir}/dovecot.conf
install -d $RPM_BUILD_ROOT/var/run/dovecot/{login,empty,token-login}

install -d $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 docinstall/example-config/dovecot.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot
install -p -m 644 docinstall/example-config/conf.d/*.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole/example-config/conf.d/*.conf $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 docinstall/example-config/conf.d/*.conf.ext $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d
install -p -m 644 $RPM_BUILD_ROOT/%{_docdir}/%{name}-pigeonhole/example-config/conf.d/*.conf.ext $RPM_BUILD_ROOT%{_sysconfdir}/dovecot/conf.d ||:

install -p -m 644 doc/dovecot-openssl.cnf $RPM_BUILD_ROOT%{ssldir}/dovecot-openssl.cnf

install -p -m755 doc/mkcert.sh $RPM_BUILD_ROOT%{_libexecdir}/%{name}/mkcert.sh

install -d $RPM_BUILD_ROOT/var/lib/dovecot

%delete_la

cd docinstall
rm -f securecoding.txt thread-refs.txt
cd -


%pre
getent group dovecot >/dev/null || groupadd -r --gid 97 dovecot
getent passwd dovecot >/dev/null || \
useradd -r --uid 97 -g dovecot -d /usr/libexec/dovecot -s /sbin/nologin -c "Dovecot IMAP server" dovecot

getent group dovenull >/dev/null || groupadd -r dovenull
getent passwd dovenull >/dev/null || \
useradd -r -g dovenull -d /usr/libexec/dovecot -s /sbin/nologin -c "Dovecot's unauthorized user" dovenull

if [ "$1" = "2" ]; then
  rm -f %restart_flag
  /bin/systemctl is-active %{name}.service >/dev/null 2>&1 && touch %restart_flag ||:
  /bin/systemctl stop %{name}.service >/dev/null 2>&1
fi

%post
if [ $1 -eq 1 ]; then
  %systemd_post dovecot.service
fi

install -d -m 0755 -g dovecot -d /var/run/dovecot
install -d -m 0755 -d /var/run/dovecot/empty
install -d -m 0750 -g dovenull -d /var/run/dovecot/login
install -d -m 0755 -g dovenull -d /var/run/dovecot/token-login
[ -x /sbin/restorecon ] && /sbin/restorecon -R /var/run/dovecot

%preun
if [ $1 = 0 ]; then
    /bin/systemctl disable dovecot.service dovecot.socket >/dev/null 2>&1 || :
    /bin/systemctl stop dovecot.service dovecot.socket >/dev/null 2>&1 || :
    rm -rf /var/run/dovecot
fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || :


if [ "$1" -ge "1" -a -e %restart_flag ]; then
    /bin/systemctl start dovecot.service >/dev/null 2>&1 || :
    rm -f %restart_flag
fi

%posttrans
if [ -e %restart_flag ]; then
    /bin/systemctl start dovecot.service >/dev/null 2>&1 || :
    rm -f %restart_flag
fi

%check
make check
cd dovecot-2*3-pigeonhole-%{pigeonholever}
make check

%files
%doc docinstall/* AUTHORS ChangeLog COPYING COPYING.LGPL COPYING.MIT NEWS README
%{_sbindir}/dovecot

%{_bindir}/{doveadm,doveconf,dsync,dovecot-sysreport}

%_tmpfilesdir/dovecot.conf
%{_unitdir}/{dovecot.service,dovecot.socket,dovecot-init.service}

%dir %{_sysconfdir}/dovecot
%dir %{_sysconfdir}/dovecot/conf.d
%config(noreplace) %{_sysconfdir}/dovecot/dovecot.conf
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{10-auth.conf,10-director.conf,10-logging.conf,10-mail.conf}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{10-master.conf,10-ssl.conf,15-lda.conf,15-mailboxes.conf}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{20-imap.conf,20-lmtp.conf,20-pop3.conf,20-submission.conf}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{90-acl.conf,90-quota.conf,90-plugin.conf,auth-checkpassword.conf.ext}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{auth-deny.conf.ext,auth-dict.conf.ext,auth-ldap.conf.ext}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{auth-master.conf.ext,auth-passwdfile.conf.ext,auth-sql.conf.ext}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{auth-static.conf.ext,auth-system.conf.ext,auth-vpopmail.conf.ext}

%config(noreplace) %{_sysconfdir}/pam.d/dovecot
%config(noreplace) %{ssldir}/dovecot-openssl.cnf

%dir %{ssldir}
%dir %{ssldir}/certs
%dir %{ssldir}/private
%attr(0600,root,root) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %{ssldir}/certs/dovecot.pem
%attr(0600,root,root) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %{ssldir}/private/dovecot.pem

%dir %{_libdir}/dovecot
%dir %{_libdir}/dovecot/{auth,dict}
%{_libdir}/dovecot/doveadm
%exclude %{_libdir}/dovecot/doveadm/*sieve*
%{_libdir}/dovecot/*.so.*
%{_libdir}/dovecot/*_plugin.so
%exclude %{_libdir}/dovecot/*_sieve_plugin.so
%{_libdir}/dovecot/auth/{lib20_auth_var_expand_crypt.so,libauthdb_imap.so,libauthdb_ldap.so}
%{_libdir}/dovecot/auth/{libmech_gssapi.so,libdriver_sqlite.so}
%{_libdir}/dovecot/dict/{libdriver_sqlite.so,libdict_ldap.so}
%{_libdir}/dovecot/{libdriver_sqlite.so,libssl_iostream_openssl.so,libfs_compress.so,libfs_crypt.so}
%{_libdir}/dovecot/{libfs_mail_crypt.so,libdcrypt_openssl.so,lib20_var_expand_crypt.so}
%{_libdir}/dovecot/old-stats/{libold_stats_mail.so,libstats_auth.so}

%dir %{_libdir}/dovecot/settings

%{_libexecdir}/%{name}

%ghost /var/run/dovecot
%attr(0750,dovecot,dovecot) /var/lib/dovecot

%{_datadir}/%{name}

%{_bindir}/{sieve-dump,sieve-filter,sieve-test,sievec}
%config(noreplace) %{_sysconfdir}/dovecot/conf.d/{20-managesieve.conf,90-sieve.conf,90-sieve-extprograms.conf}

%{_docdir}/%{name}-pigeonhole

%{_libexecdir}/%{name}/{managesieve,managesieve-login}

%{_libdir}/dovecot/doveadm/*sieve*
%{_libdir}/dovecot/*_sieve_plugin.so
%{_libdir}/dovecot/settings/{libmanagesieve_*.so,libpigeonhole_*.so}
%{_libdir}/dovecot/sieve/
%{_libdir}/%{name}/libdriver_mysql.so
%{_libdir}/%{name}/auth/libdriver_mysql.so
%{_libdir}/%{name}/dict/libdriver_mysql.so
%{_libdir}/%{name}/libdriver_pgsql.so
%{_libdir}/%{name}/auth/libdriver_pgsql.so
%{_libdir}/%{name}/dict/libdriver_pgsql.so

%exclude %{_sysconfdir}/dovecot/README

%files devel
%{_includedir}/dovecot
%{_datadir}/aclocal/dovecot*.m4
%{_libdir}/dovecot/libdovecot*.so
%{_libdir}/dovecot/dovecot-config


%files help
%{_mandir}/man1/*
%{_mandir}/man7/doveadm-search-query.7*
%{_mandir}/man7/pigeonhole.7*


%changelog
* Sat Aug 1 wangyue <wangyue92@huawei.com> - 2.3.10.1
- Upgrade to 2.3.10.1 to fix CVE-2020-10967, CVE-2020-10958, CVE-2020-10957

* Thu May 21 2020 yanan li <liyanan032@huawei.com> - 2.3.3-6
- Fix building with GCC9.

* Sun Mar 16 2020 gulining<gulining1@huawei.com> - 2.3.3-5
- Type:cves
- ID:CVE-2015-3420 CVE-2016-8652
- SUG:restart
- DESC:fix CVE-2015-3420 CVE-2016-8652

* Mon Dec 2 2019 wangzhishun <wangzhishun1@huawei.com> - 2.3.3-4
- Package init
