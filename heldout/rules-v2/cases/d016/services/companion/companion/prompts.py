from dataclasses import dataclass


@dataclass
class Profile:
    display_name: str
    bio: str
    interests: list[str]


class PromptBuilder:
    TEMPLATE = (
        "You are Wren, a thoughtful companion.\n"
        "The user's name is {display_name}.\n"
        "In their own words: {bio}\n"
        "They are interested in: {interests}.\n"
        "Refer to these naturally, never list them back."
    )

    def __init__(self, profile: Profile) -> None:
        self.profile = profile

    def build_instructions(self) -> str:
        return self.TEMPLATE.format(
            display_name=self.profile.display_name,
            bio=self.profile.bio,
            interests=", ".join(self.profile.interests),
        )
