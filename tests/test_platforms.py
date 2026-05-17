from agent.platforms.registry import detect_platform


def test_detect_platform_rhel():
    profile = detect_platform('PRETTY_NAME="Red Hat Enterprise Linux 9.4"')
    assert profile is not None
    assert profile.key == "rhel"


def test_detect_platform_rhel_from_id_like():
    profile = detect_platform('NAME="Acme Linux"\nID_LIKE="rhel fedora"')
    assert profile is not None
    assert profile.key == "rhel"


def test_detect_platform_alpine_from_id():
    profile = detect_platform('NAME="Minimal OS"\nID=alpine')
    assert profile is not None
    assert profile.key == "alpine"


def test_detect_platform_nxos():
    profile = detect_platform('Cisco Nexus Operating System (NX-OS) Software')
    assert profile is not None
    assert profile.key == "cisco_nxos"


def test_detect_platform_ios_xe():
    profile = detect_platform('Cisco IOS XE Software, Version 17.09.04a')
    assert profile is not None
    assert profile.key == "cisco_ios_xe"


def test_detect_platform_ios_classic():
    profile = detect_platform('Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8')
    assert profile is not None
    assert profile.key == "cisco_ios"
