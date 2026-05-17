from agent.platforms.alpine import ALPINE_PROFILE
from agent.platforms.base import PlatformProfile
from agent.platforms.cisco_ios import CISCO_IOS_PROFILE
from agent.platforms.cisco_ios_xe import CISCO_IOS_XE_PROFILE
from agent.platforms.cisco_nxos import CISCO_NXOS_PROFILE
from agent.platforms.rhel import RHEL_PROFILE


PLATFORM_REGISTRY: tuple[PlatformProfile, ...] = (
    RHEL_PROFILE,
    ALPINE_PROFILE,
    CISCO_IOS_XE_PROFILE,
    CISCO_IOS_PROFILE,
    CISCO_NXOS_PROFILE,
)


def detect_platform(fingerprint_text: str) -> PlatformProfile | None:
    lowered = fingerprint_text.lower()
    for profile in PLATFORM_REGISTRY:
        for hint in profile.detection_hints:
            if hint.lower() in lowered:
                return profile
    return None
