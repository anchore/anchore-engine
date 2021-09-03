class FeedDisplayMapper:
    def __init__(self):
        self._display_to_internal_map = {}
        self._internal_to_display_map = {}

    def register(self, internal_name: str, display_name: str) -> None:
        self._display_to_internal_map[display_name] = internal_name
        self._internal_to_display_map[internal_name] = display_name

    def get_display_name(self, internal_name: str) -> str:
        return self._internal_to_display_map[internal_name]

    def get_internal_name(self, display_name: str) -> str:
        return self._display_to_internal_map[display_name]
