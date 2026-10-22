#!/bin/sh
# Diagnostic image build only; never run install on a host.
set -eu
export LC_ALL=C

fail() { printf '%s\n' 'java_dependency_install_unverified' >&2; exit 2; }
hash_file() { test -f "$1" && test ! -L "$1" || fail; sha256sum "$1" | cut -d ' ' -f 1; }
canonical_keyring() {
  test "$#" = 1 || fail
  # Trixie ships .gpg as a compatibility symlink. Select the fixed canonical
  # regular file; never relax the non-symlink guard or follow arbitrary links.
  hash_file "$1/debian-archive-keyring.pgp" > /dev/null
  printf '%s/debian-archive-keyring.pgp\n' "$1"
}

check_lock() {
  test "$#" = 2 && test -f "$1" && test ! -L "$1" || fail
  test "$(wc -c < "$1" | tr -d ' ')" -le 16384 || fail
  test "$(tail -c 1 "$1" | od -An -tu1 | tr -d ' ')" = 10 || fail
  awk -F '\t' -v selected="$2" '
    function bad() { invalid=1 }
    function hash(s) { return length(s)==64 && s ~ /^[0-9a-f]+$/ }
    BEGIN { split("fontconfig fonts-dejavu-core libasound2t64 libx11-6 libxext6 libxi6 libxrender1 libxtst6",names," ");
      for(i in names) allowed[names[i]]=1; if(selected!="amd64" && selected!="arm64") bad() }
    NR==1 { if(NF!=2 || $0!="APPGUARD_JAVA_RUNTIME_LOCK\t1") bad(); next }
    NR==2 { if(NF!=2 || $0!="SNAPSHOT\t20261022T200000Z") bad(); next }
    NR==3 || NR==4 { repo=(NR==3?"debian":"debian-security"); suite=(NR==3?"trixie":"trixie-security");
      if(NF!=4 || $1!="RELEASE" || $2!=repo || $3!=suite || !hash($4)) bad(); next }
    NR>=5 && NR<=20 {
      if(NF!=7 || $1!="PACKAGE" || ($2!="amd64" && $2!="arm64") || !($3 in allowed) ||
        $4 !~ /^[0-9][A-Za-z0-9.+:~-]*$/ || length($4)>200 || !hash($6) ||
        $7 !~ /^[1-9][0-9]*$/ || $7>20000000 || ++seen[$2 SUBSEP $3]!=1 ||
        $5!=($3=="fonts-dejavu-core"?"all":$2)) bad();
      if($3=="fonts-dejavu-core") { common=$3 FS $4 FS $5 FS $6 FS $7;
        if(font!="" && font!=common) bad(); font=common }
      if($2==selected) { output=output $3 FS $4 FS $5 FS $6 FS $7 "\n"; count++ }; next }
    NR==21 { if($0!="END\t16") bad(); next }
    { bad() }
    END { if(NR!=21 || count!=8 || invalid) exit 2; printf "%s",output }
  ' "$1"
}

check_releases() {
  test "$#" = 4 || fail
  check_lock "$1" amd64 > /dev/null
  test "$(hash_file "$3")" = "$4" || fail
  for repo in debian debian-security; do
    expected=$(awk -F '\t' -v repo="$repo" '$1=="RELEASE" && $2==repo {print $4}' "$1")
    test "$(hash_file "$2/$repo.InRelease")" = "$expected" || fail
  done
}

check_downloads() {
  # Validate all resolved archives, including transitives, against the authenticated
  # APT indexes. Direct versions/hashes additionally match the committed lock.
  : > "$state/archive-hashes"
  : > "$state/archive-manifest"
  count=0; total=0
  for archive in "$state/archives"/*.deb; do
    test -f "$archive" && test ! -L "$archive" || fail
    count=$((count+1)); test "$count" -le 128 || fail
    name=$(dpkg-deb -f "$archive" Package)
    version=$(dpkg-deb -f "$archive" Version)
    architecture=$(dpkg-deb -f "$archive" Architecture)
    printf '%s\t%s\t%s\n' "$name" "$version" "$architecture" | awk -F '\t' -v arch="$arch" '
      NF!=3 || $1 !~ /^[a-z0-9][a-z0-9+.-]*$/ || $2 !~ /^[0-9][A-Za-z0-9.+:~-]*$/ ||
      ($3!=arch && $3!="all") {exit 2}' || fail
    digest=$(hash_file "$archive"); size=$(stat -c %s "$archive")
    test "$size" -gt 0 && test "$size" -le 20000000 || fail
    total=$((total+size)); test "$total" -le 100000000 || fail
    timeout 30 apt-cache -o Dir::State::lists="$state/lists" show "$name=$version" > "$state/package-metadata"
    test "$(stat -c %s "$state/package-metadata")" -le 100000 || fail
    awk -v package="$name" -v version="$version" -v arch="$architecture" -v digest="$digest" -v size="$size" '
      BEGIN {RS=""; FS="\n"}
      {delete f; for(i=1;i<=NF;i++) {p=index($i,": "); if(p>0) {
        key=substr($i,1,p-1);
        if(key=="Package" || key=="Version" || key=="Architecture" || key=="SHA256" || key=="Size") {
          if(key in f) invalid=1; f[key]=substr($i,p+2) } }}
        if(f["Package"]==package && f["Version"]==version && f["Architecture"]==arch && f["SHA256"]==digest && f["Size"]==size) found=1}
      END {if(!found || invalid) exit 2}' "$state/package-metadata" || fail
    printf 'ARCHIVE\t%s\t%s\t%s\t%s\t%s\n' "$name" "$version" "$architecture" "$digest" "$size" >> "$state/archive-manifest"
    sha256sum "$archive" >> "$state/archive-hashes"
  done
  sort "$state/archive-manifest" > "$evidence/apt-archives.tsv"
  awk -F '\t' '++seen[$2 SUBSEP $4]!=1 {exit 2}' "$evidence/apt-archives.tsv" || fail
  awk 'NR==FNR {wanted["ARCHIVE\t" $0]=1; next} $0 in wanted {seen[$0]++}
    END {for(row in wanted) if(seen[row]!=1) exit 2}' "$state/direct.tsv" "$evidence/apt-archives.tsv" || fail
}

case "${1-}" in
  check-keyring)
    test "$#" = 3 || fail
    selected_keyring=$(canonical_keyring "$2")
    test "$(hash_file "$selected_keyring")" = "$3" || fail
    exit;;
  check-lock) test "$#" = 3 || fail; check_lock "$2" "$3"; exit;;
  check-releases) test "$#" = 5 || fail; check_releases "$2" "$3" "$4" "$5"; exit;;
  check-downloads)
    test "$#" = 5 || fail
    lock=$2; arch=$3; state=$4; evidence=$5
    test -d "$state/archives" && test -d "$evidence" || fail
    check_lock "$lock" "$arch" > "$state/direct.tsv"
    check_downloads; exit;;
  install) test "$#" = 1 && test "$(id -u)" = 0 || fail;;
  *) fail;;
esac

evidence=/usr/share/appguard-java-runtime
state=/var/lib/appguard-java-runtime
lock="$evidence/dependencies.lock"
test ! -e "$state" || fail
# Public package metadata is root-owned/nonwritable but traversable by APT's
# unprivileged download user. Do not force APT to fall back to root downloads.
mkdir -m 755 "$state"
arch=$(dpkg --print-architecture)
check_lock "$lock" "$arch" > "$state/direct.tsv"
keyring=$(canonical_keyring /usr/share/keyrings)
keyring_hash=$(hash_file "$keyring")
lock_hash=$(hash_file "$lock")
mkdir -m 755 "$state/archives" "$state/lists"
mkdir -m 700 "$state/original-sources"
mkdir -m 700 "$state/archives/partial" "$state/lists/partial"

# Retain original source configuration outside APT source discovery. Only the
# two fixed past snapshots can supply this solve. No OS CA package is needed:
# APT must authenticate InRelease with the pinned-base archive keyring, then
# authenticate package indexes/archive hashes. Never allow insecure repositories.
if test -f /etc/apt/sources.list; then mv /etc/apt/sources.list "$state/original-sources/sources.list"; fi
for source in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  if test -f "$source"; then mv "$source" "$state/original-sources/"; fi
done
cat > /etc/apt/sources.list.d/appguard-runtime.sources <<SOURCES
Types: deb
URIs: http://snapshot.debian.org/archive/debian/20261022T200000Z/
Suites: trixie
Components: main
Architectures: $arch
Signed-By: $keyring
Check-Valid-Until: no

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/20261022T200000Z/
Suites: trixie-security
Components: main
Architectures: $arch
Signed-By: $keyring
Check-Valid-Until: no
SOURCES

apt_get() {
  timeout 300 apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 \
    -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false \
    -o APT::Get::AllowUnauthenticated=false \
    -o Dir::State::lists="$state/lists" -o Dir::Cache::archives="$state/archives" "$@"
}

# Fresh private lists plus error-on-any prevent an old cache from concealing a
# failed signature/download. The retained signed releases must match both pins.
apt_get update --error-on=any
for repo in debian debian-security; do
  suite=trixie; test "$repo" != debian-security || suite=trixie-security
  release="$state/lists/snapshot.debian.org_archive_${repo}_20261022T200000Z_dists_${suite}_InRelease"
  expected=$(awk -F '\t' -v repo="$repo" '$1=="RELEASE" && $2==repo {print $4}' "$lock")
  test "$(hash_file "$release")" = "$expected" || fail
  cp "$release" "$evidence/$repo.InRelease"
done

verify_inputs() {
  test "$(hash_file "$lock")" = "$lock_hash" || fail
  check_releases "$lock" "$evidence" "$keyring" "$keyring_hash"
}
verify_inputs
set --
while IFS="$(printf '\t')" read -r name version architecture digest size; do
  set -- "$@" "$name=$version"
done < "$state/direct.tsv"
export DEBIAN_FRONTEND=noninteractive
apt_get --download-only --reinstall --no-install-recommends --no-remove -y install "$@"

check_downloads
verify_inputs
sha256sum -c "$state/archive-hashes"
apt_get --no-download --reinstall --no-install-recommends --no-remove -y install "$@"
verify_inputs

while IFS="$(printf '\t')" read -r tag name version architecture digest size; do
  installed=$(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}' "$name")
  test "$installed" = "$(printf '%s\t%s\t%s\tinstalled' "$name" "$version" "$architecture")" || fail
done < "$evidence/apt-archives.tsv"
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n' > "$state/installed-all"
awk -F '\t' 'NF!=4 || $4!="installed" {exit 2} {print "INSTALLED\t" $1 "\t" $2 "\t" $3}' \
  "$state/installed-all" > "$state/installed-manifest"
sort "$state/installed-manifest" > "$evidence/installed-packages.tsv"
printf 'VERIFY\tapt-signatures\ttrue\nVERIFY\tarchive-hashes\ttrue\nVERIFY\tinstalled-identities\ttrue\nKEYRING\t%s\n' \
  "$keyring_hash" > "$evidence/verification.tsv"
chmod 444 "$evidence"/*
printf '%s\n' 'java_dependency_install_verified'
