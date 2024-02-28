from flask_restful import Api
from flask_jwt_extended import JWTManager
import random
import os
from flask_cors import CORS

from flask import Flask, request
def create_app(config_name, settings_module='config.ProductionConfig'):
    app=Flask(__name__)
    app.config.from_object(settings_module)
    return app


settings_module = os.getenv('APP_SETTINGS_MODULE','config.ProductionConfig')
application = create_app('default', settings_module)
app_context=application.app_context()
app_context.push()


import enum
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields
from sqlalchemy import DateTime, Date
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class UserType(enum.Enum):
    EMPRESA = 1
    CANDIDATO = 2
    EMPLEADO_ABC = 3

class Usuario(db.Model):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.Unicode(128), nullable=False, default='MISSING', unique=True)
    password = db.Column(db.Unicode(256))
    tipo = db.Column(db.Enum(UserType), nullable=False)  

    def set_password(self, password):
        self.password = generate_password_hash(password)

    @property
    def is_authenticated(self):
        return self._authenticated

    def authenticate(self, password):
        checked = check_password_hash(self.password, password)
        self._authenticated = checked
        return self._authenticated

    def __init__(self, *args, **kw):
        super(Usuario, self).__init__(*args, **kw)

    def get_id(self):
        return self.id

    def save(self):
        if not self.id:
            db.session.add(self)
        db.session.commit()

    @staticmethod
    def get_by_id(id):
        return Usuario.query.get(id)

    @staticmethod
    def get_by_nombre(nombre):
        return Usuario.query.filter_by(nombre=nombre).first()

    @staticmethod
    def get_count():
        return Usuario.query.count()

class EnumADiccionario(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return None
        else:
            return value.name #{'llave':value.name, 'valor':value.value} #{value.name}  #{'llave':value.name, 'valor':value.value}
    
class UsuarioSchema(SQLAlchemyAutoSchema):
    tipo=EnumADiccionario(attribute=('tipo'))
    class Meta:
        model = Usuario
        include_relationships = True
        load_instance = True

usuario_schema = UsuarioSchema()

db.init_app(application)
db.create_all()


CORS(application)


from flask import request
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
#from auth.modelos.modelos import db, Usuario, UsuarioSchema, UserType


usuario_schema = UsuarioSchema()

class VistaSignIn(Resource):   
    def post(self):
        tipo = request.json.get('tipo', None)
        pass1 = request.json.get('password', None)
        pass2 = request.json.get('password2', None)
        nombre = request.json.get('nombre', None)
        if tipo is not None and pass1 is not None and pass2 is not None and nombre is not None:
            if UserType.EMPRESA.name==tipo or UserType.CANDIDATO.name==tipo or UserType.EMPLEADO_ABC.name==tipo:
                if pass1==pass2:
                    usuario=Usuario.query.filter(Usuario.nombre == nombre).first()
                    if usuario is None:
                        nuevo_usuario = Usuario(nombre=nombre, tipo=UserType[tipo])
                        nuevo_usuario.set_password(pass1)
                        db.session.add(nuevo_usuario)
                        db.session.commit()
                        additional_claims = {"aud": nuevo_usuario.tipo.name, "MyUserType": nuevo_usuario.tipo.name}
                        token_de_acceso = create_access_token(identity=nuevo_usuario.id, additional_claims=additional_claims)
                        return {"mensaje": "usuario creado exitosamente", "token": token_de_acceso, "id": nuevo_usuario.id, "tipo": nuevo_usuario.tipo.name}, 200
                    else:
                        return {"mensaje": "Usuario Ya Existe"}, 401
                else:
                    return {"mensaje": "No coincide password de confirmación"}, 400
            else:
                return {"mensaje": "Valor Invalido para Tipo de Usuario"}, 404
        else:
            return {"mensaje": "Faltan algunos datos necesarios"}, 400

class VistaLogIn(Resource):
    def post(self):
        pass1 = request.json.get('password', None)
        nombre = request.json.get('nombre', None)
        if nombre is not None and pass1 is not None:
            usuario = Usuario.query.filter(Usuario.nombre == nombre).first()
            db.session.commit()
            if usuario is not None:
                if usuario.authenticate(pass1):
                    additional_claims = {"aud": usuario.tipo.name, "MyUserType": usuario.tipo.name}
                    token_de_acceso = create_access_token(identity=usuario.id, additional_claims=additional_claims)
                    return {"mensaje": "Inicio de sesión exitoso", "token": token_de_acceso, "id": usuario.id, "tipo": usuario.tipo.name}
                else:
                    return {"mensaje":"LogIn Incorrecto. Password Incorrecta."}, 401               
            else:
                return {"mensaje":"LogIn Incorrecto. El nombre de usuario NO existe."}, 404
        else:
            return {"mensaje": "Faltan datos necesarios"}, 400
        
class VistaUsuario(Resource):   
    def get(self, id_usuario):
        usuario = Usuario.query.get_or_404(id_usuario)
        return usuario_schema.dump(usuario)

    def put(self, id_usuario):
        usuario = Usuario.query.get_or_404(id_usuario)
        if request.json.get("password", None) is not None:
           usuario.set_password(request.json["password"])
        usuario.nombre=request.json.get("nombre", usuario.nombre)
        db.session.commit()
        return usuario_schema.dump(usuario)

    def delete(self, id_usuario):
        usuario = Usuario.query.get_or_404(id_usuario)
        db.session.delete(usuario)
        db.session.commit()
        return "Usuario Borrado.",  204

class VistaAuthorization(Resource):
    @jwt_required()
    def post(self):
        id_usuario = get_jwt_identity()
        usuario = Usuario.query.get_or_404(id_usuario)
        if usuario is not None:
            roles=request.json.get("roles", None)
            if roles is not None:
                if len(roles)!=0:
                    claims = get_jwt()  #claims = get_jwt_claims()
                    autorizado=False
                    for r in roles:
                        if claims['MyUserType'] == r:
                            autorizado=True
                    if autorizado:
                        return {"Mensage":"Usuario Autorizado", "id": usuario.id, "authorization": 1, "rol": usuario.tipo.name}, 200
                    else:
                        return {"Mensage":"Usuario Desautorizado", "id": usuario.id, "authorization": None, "rol": usuario.tipo.name}, 404
                else:
                    return {"Mensage":"Usuario Autorizado", "id": usuario.id, "authorization": 1, "rol": usuario.tipo.name}, 200
            else:
                return {"Mensage":"Peticion incorrecta", "id": usuario.id, "authorization": None, "rol": usuario.tipo.name}, 404 
        else:
            return {"Mensage":"Usuario no existe", "id": id_usuario, "authorization": None, "rol": "DESCONOCIDO"}, 404
        

class VistaPing(Resource):
    def get(self):
        print("pong")
        return {"Mensaje":"Pong"}, 200


api = Api(application)
api.add_resource(VistaSignIn, '/auth/signup')
api.add_resource(VistaLogIn, '/auth/login')
api.add_resource(VistaUsuario, '/usuario/<int:id_usuario>')
api.add_resource(VistaAuthorization, '/auth/me')
api.add_resource(VistaPing, '/auth/ping')


jwt = JWTManager(application)

if Usuario.get_count()==0:
    print("Creando Usuarios.")
    regT=0  #"id","nombre","password","tipo"
    with open("./usuario.csv") as archivo:
        for linea in archivo:
            try:
                campos=linea.split(sep=',')
                cn=Usuario()
                nombre=campos[1]
                password=campos[2]
                tipo=campos[3]

                nombre=nombre[1:-1]
                password=password[1:-1]
                tipo=tipo[1:-2]

                cn.nombre=nombre
                cn.password=password
                cn.tipo=UserType[tipo]
                db.session.add(cn)
                db.session.commit()
                regT=regT+1
                #print("=====================")
                #print(cn.id)
                #print(regT)
            except Exception as inst:
                db.session.rollback()
                print(type(inst))    # the exception instance
                #print(inst)
                print("Usuario no se pudo crear.")

if Usuario.get_count()==0 and False:
    print("Creando Usuarios.")
    regT=0  #Usuario, Tipo
    with open("./usuarios.txt") as archivo:
        for linea in archivo:
            try:
                campos=linea.split(sep='|')
                cn=Usuario()
                cn.nombre=campos[0]
                cn.tipo=UserType[campos[1]]
                cn.set_password("12345678")
                db.session.add(cn)
                db.session.commit()
                regT=regT+1
                print("=====================")
                print(cn.id)
                print(regT)
            except Exception as inst:
                db.session.rollback()
                print(type(inst))    # the exception instance
                print(inst)
                print("Usuario no se pudo crear.")

if Usuario.get_count()==0 and False:
    registros=0
    for i in range(33505):
        try:
            un=Usuario()
            if i<33000:
                un.nombre="UserCand"+str(i+1)
                un.tipo='CANDIDATO'
            elif i>=33000 and i<33500:
                un.nombre="UserEmp"+str(i+1)
                un.tipo='EMPRESA'
            else:
                un.nombre="UserABC"+str(i+1)
                un.tipo='EMPLEADO_ABC'
            un.set_password('12345678')
            db.session.add(un)
            db.session.commit()
            registros=registros+1
            print("====================")
            print(registros)
        except Exception as inst:
            db.session.rollback()
            print(type(inst))    # the exception instance
            #print(inst)
            print("Usuario no se pudo guardar.")

if False:
    with open("./usuarios.txt", "xt+") as archivo:
        registros=0
        nombre=""
        tipo=""
        for i in range(33505):
            try:
                if i<33000:
                    nombre="UserCand"+str(i+1)
                    tipo='CANDIDATO'
                elif i>=33000 and i<33500:
                    nombre="UserEmp"+str(i+1)
                    tipo='EMPRESA'
                else:
                    nombre="UserABC"+str(i+1)
                    tipo='EMPLEADO_ABC'
                linea=nombre+"|"+tipo+"\n"                        
                print(linea)
                archivo.write(linea)
                registros=registros+1
                print("====================")
                print(registros)
            except Exception as inst:
                db.session.rollback()
                print(type(inst))    # the exception instance
                print(inst)
                print("Usuario no se pudo generar.")