Name:           lh-kernel-preempt-patch
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-preempt - Deterministic Worst-Case Execution Time & Jitter Bound
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
C11 Real-Time Linux 6.6 LTS PREEMPT_RT kernel patchset verifier, deterministic Worst-Case Execution Time (WCET) & cyclictest jitter analyzer, and 10-rule RT posture auditor for NVIDIA Jetson Orin (tegra234).

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-preempt ]; then
    install -m 0755 bin/lh-preempt %{buildroot}%{_bindir}/lh-preempt
elif [ -f lh-preempt ]; then
    install -m 0755 lh-preempt %{buildroot}%{_bindir}/lh-preempt
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for lh-kernel-preempt-patch.
