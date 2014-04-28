from unittest import TestCase
from unittest import makeSuite


class MyAppTest(TestCase):

    def test_nothing(self):
        pass


def test_suite():
    return makeSuite(MyAppTest)
