import unittest
from app.models import User

class UserModelTestCase(unittest.TestCase):
    def test_no_password_getter(self):
        u = User(password='cat')
        with self.assertRaises(AttributeError):
            u.password

    def test_verify_password(self):
        u = User(password='cat')
        self.assertTrue(u.verify_password('cat'))
        self.assertFalse(u.verify_password('dog'))

    def test_password_setter(self):
        u = User()
        self.assertIsNone(u.password_hash)
        u.password = 'cat'
        self.assertTrue(u.password_hash)

    def test_password_is_random(self):
        u1 = User(password='cat')
        u2 = User(password='cat')
        self.assertNotEqual(u1.password_hash, u2.password_hash)

