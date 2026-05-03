class OptionalAIExplainer:
    """Optional extension point for local or hosted AI explanations.

    LeakShield Pro does not require this module. The production explanation path is deterministic
    and rule-based. Teams can wire this class to an approved internal model if policy allows it.
    """

    async def enrich(self, rule_based_explanation: dict[str, str]) -> dict[str, str]:
        return rule_based_explanation

