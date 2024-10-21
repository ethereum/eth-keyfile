from typing import (
    Any,
    Optional,
)


class EthKeyfileException(Exception):
    """
    Exception mixin inherited by all exceptions of eth-keyfile

    This allows::

        try:
            some_call()
        except EthKeyfileException:
            # deal with eth-keyfile exception
        except:
            # deal with other exceptions
    """

    user_message: Optional[str] = None

    def __init__(
        self,
        *args: Any,
        user_message: Optional[str] = None,
    ):
        super().__init__(*args)

        # Assign properties of EthKeyfileException
        self.user_message = user_message


class EthKeyfileNotImplementedError(EthKeyfileException, NotImplementedError):
    """
    An eth-keyfile exception wrapper for `NotImplementedError`, for better control over
    exception handling
    """


class EthKeyfileValueError(EthKeyfileException, ValueError):
    """
    An eth-keyfile exception wrapper for `ValueError`, for better control over
    exception handling
    """


class EthKeyfileTypeError(EthKeyfileException, TypeError):
    """
    An eth-keyfile exception wrapper for `TypeError`, for better control over
    exception handling
    """
