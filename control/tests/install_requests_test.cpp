#include "omarchy-kids-control/install_requests.h"
#include "omarchy-kids-control/notify.h"

#include <gtest/gtest.h>

#include <algorithm>

using namespace omarchy_kids::control;

namespace {

HostEntry sampleHost() {
    HostEntry host;
    host.name = "Finn";
    host.hostname = "10.0.0.183";
    host.sshPort = 22;
    host.username = "finn";
    return host;
}

bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

} // namespace

TEST(InstallRequests, OrdinaryPackageNamesAreValid) {
    for (const char* name : {"gimp", "minecraft-launcher", "lib32-glibc", "python-numpy", "g++", "gtk4", "a"}) {
        EXPECT_TRUE(isValidPackageName(name)) << name;
    }
}

// The agent runs as the child, so this list is what stops a tampered agent
// from getting an option or a shell command into a root command line.
TEST(InstallRequests, NamesThatCouldBeOptionsOrShellTricksAreRefused) {
    for (const char* name : {"", "-S", "--overwrite", ".hidden", "UPPER", "with space", "a;b", "a&&b", "$(id)",
                             "a`b`", "a/b", "../x", "tab\there", "new\nline", "a'b", "a\"b", "a|b", "a>b"}) {
        EXPECT_FALSE(isValidPackageName(name)) << "[" << name << "]";
    }
    EXPECT_FALSE(isValidPackageName(std::string(101, 'a')));
}

TEST(InstallRequests, LoginNamesAndHostsAreChecked) {
    EXPECT_TRUE(isValidLoginName("evan"));
    EXPECT_TRUE(isValidLoginName("_svc-1"));
    for (const char* bad : {"", "Evan", "1evan", "-evan", "ev an", "evan;id", "ev@n"}) {
        EXPECT_FALSE(isValidLoginName(bad)) << bad;
    }
    EXPECT_TRUE(isValidSshHost("10.0.0.183"));
    EXPECT_TRUE(isValidSshHost("finn-alienware.local"));
    EXPECT_TRUE(isValidSshHost("fe80::1"));
    for (const char* bad : {"", "-oProxyCommand=id", "a b", "a;b", "a/b", "$(id)"}) {
        EXPECT_FALSE(isValidSshHost(bad)) << bad;
    }
}

TEST(InstallRequests, AdminInstallCommandIsExactlyTheExpectedSudoPacmanLine) {
    const auto argv = adminInstallSshArgs(sampleHost(), "evan", "gimp", "/keys/Finn.admin_known_hosts");

    ASSERT_FALSE(argv.empty());
    EXPECT_EQ(argv.front(), "ssh");
    EXPECT_TRUE(contains(argv, "-t")); // a terminal, so sudo can ask for the password
    EXPECT_TRUE(contains(argv, "StrictHostKeyChecking=yes"));
    EXPECT_TRUE(contains(argv, "UserKnownHostsFile=/keys/Finn.admin_known_hosts"));
    EXPECT_TRUE(contains(argv, "HostKeyAlias=omarchy-kids-child"));

    // The tail is the destination followed by the remote command, in order.
    const std::vector<std::string> tail(argv.end() - 7, argv.end());
    const std::vector<std::string> expected = {"evan@10.0.0.183", "sudo", "pacman", "-S", "--needed", "--", "gimp"};
    EXPECT_EQ(tail, expected);
    // Interactive on purpose: never --noconfirm.
    EXPECT_FALSE(contains(argv, "--noconfirm"));
}

TEST(InstallRequests, WithoutAPinnedKeyTheFirstConnectionIsTrustedOnFirstUse) {
    const auto argv = adminInstallSshArgs(sampleHost(), "evan", "gimp", "");
    ASSERT_FALSE(argv.empty());
    EXPECT_TRUE(contains(argv, "StrictHostKeyChecking=accept-new"));
    EXPECT_FALSE(contains(argv, "StrictHostKeyChecking=yes"));
}

TEST(InstallRequests, NothingIsBuiltFromUnvalidatedInput) {
    EXPECT_TRUE(adminInstallSshArgs(sampleHost(), "evan", "gimp; rm -rf /", "").empty());
    EXPECT_TRUE(adminInstallSshArgs(sampleHost(), "evan", "--overwrite", "").empty());
    EXPECT_TRUE(adminInstallSshArgs(sampleHost(), "evan;id", "gimp", "").empty());
    EXPECT_TRUE(adminInstallSshArgs(sampleHost(), "", "gimp", "").empty());

    HostEntry badHost = sampleHost();
    badHost.hostname = "-oProxyCommand=touch /tmp/x";
    EXPECT_TRUE(adminInstallSshArgs(badHost, "evan", "gimp", "").empty());
}

TEST(InstallRequests, RequestKeyDistinguishesAResetAgentDatabase) {
    InstallRequest a;
    a.id = 1;
    a.requestedAt = "2026-09-21T10:00:00Z";
    InstallRequest b = a;
    b.requestedAt = "2026-09-25T10:00:00Z"; // same id, after the child's agent database was reset
    EXPECT_NE(requestKey("Finn", a), requestKey("Finn", b));
    EXPECT_NE(requestKey("Finn", a), requestKey("Kim", a));
    EXPECT_EQ(requestKey("Finn", a), requestKey("Finn", a));
}

TEST(Notify, TextIsStrippedOfControlCharactersAndCapped) {
    EXPECT_EQ(sanitizeNotificationText("Finn wants gimp"), "Finn wants gimp");
    EXPECT_EQ(sanitizeNotificationText("a\x1b[31mred\x07\nb"), "a[31mredb");
    EXPECT_EQ(sanitizeNotificationText("gr\xc3\xbc\xc3\x9f" "e"), "gr\xc3\xbc\xc3\x9f" "e"); // UTF-8 untouched
    EXPECT_EQ(sanitizeNotificationText(std::string(500, 'x'), 50).size(), 50u);
    EXPECT_EQ(sanitizeNotificationText(""), "");
}
