import json
import time
from flask import Response
from flask_jwt_extended import create_access_token
from datetime import timedelta

from unittest import TestCase
from unittest.mock import Mock, patch
import uuid 

from application import application

class testBlackList(TestCase):

    def setUp(self):
        print("setUp")
        self.client=application.test_client()
        self.tokenfijo="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY4MDYyMzQwNCwianRpIjoiZmVjYTI5NTAtY2I1My00ZWVkLWFiN2ItZjM5ZTMwMDg2NzkxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MSwibmJmIjoxNjgwNjIzNDA0fQ.aF924YU7GlLR_u6YuFZeZgul2o75ltDYrNkIC6e4a4Q"
        self.userId=2
        self.offerId=1
        self.postId=1
        access_token_expires = timedelta(minutes=120)
        self.token=create_access_token(identity=self.userId, expires_delta=access_token_expires)
        access_token_expires = timedelta(seconds=3)
        self.tokenexpired=create_access_token(identity=self.userId, expires_delta=access_token_expires)
        #self.token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY3NTczMTY3MywianRpIjoiOGU1OWJjZmQtNTJlYi00YzQ1LWI1NDUtZTU3MGYxMDBiNTQ0IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MiwibmJmIjoxNjc1NzMxNjczLCJleHAiOjE2NzU3Mzg4NzN9.iPaNwx0Sp2TcPOyv5p12e7RyPAUDih3lrLxV0mVN43Q"
        #self.tokenexpired="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY3NTY4NDg3NiwianRpIjoiZjdkYzNlN2QtMzFhNy00NWZhLTg3NjItNzIwZDQ0NTUyMWZjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6MiwibmJmIjoxNjc1Njg0ODc2LCJleHAiOjE2NzU2ODY2NzZ9.fPQFhAK_4k16NqpMGcT2eV-q-PQRUKHrLMiQY-xzDYM"


    def test_ping(self):
        endpoint_ping='/auth/ping'
        solicitud_ping=self.client.get(endpoint_ping)
        respuesta_ping=json.loads(solicitud_ping.get_data())
        msg=respuesta_ping["Mensaje"]
        self.assertEqual(solicitud_ping.status_code, 200)
        self.assertIn("Pong", msg)

    def test_prueba_usuario(self):
        headers={
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(self.tokenfijo)
        }

        endpoint_usuario='/auth/signup'

        unico=str(uuid.uuid1())
        nombre_usuario="User"+unico
        nuevo_usuario={
            "nombre":nombre_usuario,
            "password":"12345",
            "password2":"12345",
            "tipo":"EMPRESA"
        }


        solicitud_crear=self.client.post(endpoint_usuario, 
                                                data=json.dumps(nuevo_usuario), 
                                                headers=headers)
        respuesta_crear=json.loads(solicitud_crear.get_data())
        self.assertEqual(respuesta_crear['mensaje'], "usuario creado exitosamente")
        self.assertEqual(solicitud_crear.status_code, 200)


        endpoint_login='/auth/login'
        usuario_login={
                "nombre":nombre_usuario,
                "password":"12345"
        }
        solicitud_login=self.client.post(endpoint_login, 
                                                data=json.dumps(usuario_login), 
                                                headers=headers)
        respuesta_login=json.loads(solicitud_login.get_data())
        self.assertEqual(respuesta_login['mensaje'], "Inicio de sesión exitoso")
        self.assertEqual(solicitud_login.status_code, 200)


        endpoint_login='/auth/login'
        usuario_login={
                "nombre":"XyZ12345QwertY09",
                "password":"nopass"
        }
        solicitud_login=self.client.post(endpoint_login, 
                                                data=json.dumps(usuario_login), 
                                                headers=headers)
        respuesta_login=json.loads(solicitud_login.get_data())
        self.assertEqual(respuesta_login['mensaje'], "LogIn Incorrecto. El nombre de usuario NO existe.")
        self.assertEqual(solicitud_login.status_code, 404)