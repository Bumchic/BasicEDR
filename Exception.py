
class No_User_From_Query(Exception):

    def __init__(self, message) -> None:
        super().__init__(message)

class user_already_exist(Exception):
    def __init__(self, message) -> None:
        super().__init__(message)
    