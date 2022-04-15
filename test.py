import unittest
import requests
import json

# if __name__ == "__main__":
#     unittest.main()

API_URL = "http://127.0.0.1:8000"
SIGNUP_URL = "{}/signup/".format(API_URL)
LOGIN_URL = "{}/login".format(API_URL)
PASS_CHANGE_URL = "{}/change_password/".format(API_URL)

class ApiTest(unittest.TestCase):
    def test_signup(self):
        test_data = json.dumps({
            'email': 'test121231@gmail.com',
            'password': 'password123',
            'first_name': 'admam',
            'last_name': 'james',
        })
        request = requests.post(SIGNUP_URL,test_data)
        self.assertEqual(request.status_code,201)
        
    def test_login(self):
        test_data = json.dumps({
            'email': 'test121231@gmail.com',
            'password': 'password123',
        })
        request = requests.post(LOGIN_URL,test_data)
        self.assertEqual(request.status_code,200)

 