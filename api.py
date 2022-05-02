#run using:
#uvicorn filename(without .py):app --reload

# import uuid
from uuid import uuid4
from fastapi import FastAPI, Depends, HTTPException, Request,Body
from fastapi_sqlalchemy import DBSessionMiddleware, db
from datetime import datetime, timezone
# from starlette.responses import  RedirectResponse #for redirecting to another internal URL

# import os
# from dotenv import load_dotenv
# load_dotenv('env')#load database details from .env file
import bcrypt
import re
import uvicorn
import env

#for mailing
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

#imports from our files
from auth import AuthHandler
from model import User as ModelUser
from model import Password_tokens
from schema import User as SchemaUser
from schema import LoginSchema
from schema import PasswordResetSchema,PasswordChangeSchema


#---------------------------!!!!!!!!!Datababse_entries!!!!!!!!!!!!!!-------------------------------------
import json
import secrets
from ast import literal_eval

# import copy
# doc.config = copy.deepcopy(doc.config)
#https://amercader.net/blog/beware-of-json-fields-in-sqlalchemy/

from schema import CustomFieldSchema, NodeSchema, ConnectionSchema
from model import Node, NodeType, Connections, CustomFields, CustomFieldTypes

app = FastAPI()

# # to avoid csrftokenError/cookie related error
app.add_middleware(DBSessionMiddleware, db_url =  env.DATABASE_URL)

#make an object of the AuthHandler class from the auth.py file
auth_handler = AuthHandler()



@app.get("/")
async def root():
    return {"message": "hello world"}

#validate the user, check if the details entered by the user can be used for making a new account
def validate_user(user:ModelUser):
    """
    Checks if email id already exists, is valid and passowrd in greater than 6 chararcters. Takes ModelUser as input
    """
    
    if(bool(db.session.query(ModelUser).filter_by(email = user.email).first())):
        raise HTTPException(status_code=400, detail='Mail already exists')

    elif not (re.fullmatch(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+$', user.email)):
        raise HTTPException(status_code=400, detail='Enter valid email')

    elif (len(user.password) < 7):
        raise HTTPException(status_code=400, detail='Password must be greater than 6 characters')

    elif not (re.fullmatch(r'[a-zA-Z]+$', user.first_name) and re.fullmatch(r'[A-Za-z]+$', user.last_name)):
        raise HTTPException(status_code=400, detail='Enter valid name')

    else:
        return True


@app.post("/signup/", status_code=201 )
async def signup(user: SchemaUser):
    """
    Validates user details and enters all details including hashed password to the database, takes User from schema.py as input.
    Returns error message if any problem, Signup Successful message if successful.
    """
    #if the details entered by the user are invalid, then return respective Exception using the self-defined validate_user function
    validated_user = validate_user(user)
    if (validated_user != True): 
        return validated_user

    #else register the user by adding its details to the database
    else:
        #create a hashed/encrypted password using bcrypt
        hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())

        #create a ModelUser instance with the details entered
        db_user = ModelUser(email = user.email, password = hashed_password.decode('utf-8'), first_name = user.first_name, last_name = user.last_name, created_at = datetime.now(timezone.utc))

        #add the ModelUser object(db_user) to the database
        db.session.add(db_user)
        db.session.commit()
        return {'message': "Signup Successful"}


#get details of the user if the email_id entered is valid, else return False
async def get_user_by_email(my_email: str):
    """
    Checks if the email exists in the DB. If not, returns false. If it does, returns all details of the user in User Model form from models.py.
    """
    user = db.session.query(ModelUser).filter_by(email=my_email).first()

    #if email id does not exist in the db, return false
    if(user == None):
        return False

    #return all details of the user
    return ModelUser(id = user.id, email=user.email, password=user.password, first_name=user.first_name, last_name = user.last_name, register_time=user.register_time)

@app.post("/login/")
async def authenticate_user(input_user: LoginSchema):
    user = await get_user_by_email(input_user.email)

    if (not user) or (not bcrypt.checkpw(input_user.password.encode('utf-8'), user.password.encode('utf-8'))):
        raise HTTPException(status_code=401, detail='Invalid username or password')

    else:   
        #generate/encode and return JWT token 
        token = auth_handler.encode_token(input_user.email)
        return {'token':token, 'message': 'Details are correct'}#valid for 1 minute and 30 seconds, change expiration time in auth.py


@app.get('/protected')
def protected(request: Request, email = Depends(auth_handler.auth_wrapper)):
    """
    The auth.py file has the function auth_wrapper which validates the token by decoding it and checking the credentials.
    Using that function , the details can only be accessed if there is valid JWT token in the header
    This function is only to demonstrate that. To run this:
    curl --header "Authorizaion: Bearer entertokenhere" localhost:8000/protected
    """
    return {'email': email}


def send_mail(my_uuid:str):
    """
    send password reset email to user via sendgrid.
    """
    # gmail id:testforfastapi@gmail.com, password:testforfastapi@99(or 00)
    # sendgrid id:gmailid, password:forfastapitest@99(or 00)

    message = Mail(
    from_email='testforfastapi@gmail.com',
    to_emails='testforfastapi@gmail.com',
    subject='Password Reset',
    html_content = 'Hello! <p> Your UUID is:<p> 127.0.0.1:8000/reset_password_link?my_uuid=' + str(my_uuid) +"<p> The link will expire in 10 minutes.")
    try:
        sg = SendGridAPIClient('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')
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
        return {'message': 'Link sent, please check mail'}
    except Exception as e:
        raise HTTPException(status_code=400, detail='Sorry!We could not send the link right now')


@app.post('/request_change_password')
async def req_change_password(email_id : str):
    my_email =  email_id

    #check if the user exists in the users database
    user = db.session.query(ModelUser).filter_by(email = my_email).first()

    #if email id does not exist in the db, return false
    if(user == None):
        raise HTTPException(status_code=400, detail = 'The user is not registered')
    my_id = user.id

    #if the user exists, generate uuid
    my_uuid = uuid4()

    #add the id, uuid and generated time to password_tokens database and add the ModelUser object(db_user) to the database
    db_user = Password_tokens(id = my_id, uuid = str(my_uuid), time = datetime.now(timezone.utc), used = False)
    
    db.session.merge(db_user)
    db.session.commit()
    
    #PRINT UUID FOR CHECKING PURPOSES
    print(my_uuid)

    #send email
    return send_mail(my_uuid)    
    # return user



def get_uuid_details(my_uuid:str):
    """
    get id and time generated of the entered uuid
    """
    try:
        user = db.session.query(Password_tokens).filter_by(uuid = str(my_uuid)).first()
    except:
        raise HTTPException(status_code=400, detail='UUID entered incorrectly')

    #if email id does not exist in the db, return false
    if(user == None):
        raise HTTPException(status_code=400, detail='UUID not found')

    #return all details of the user
    return Password_tokens(id = user.id, uuid = my_uuid, time = user.time, used = user.used)


# get details of the user if the email_id entered is valid, else return False
async def get_user_by_id(my_id: int):
    user = db.session.query(ModelUser).filter_by(id = my_id).first()
    #if email id does not exist in the db, return false
    if(user == None):
        return False
    #return all details of the user
    return ModelUser(id = my_id, email=user.email, password=user.password, first_name=user.first_name, last_name = user.last_name, register_time = user.register_time)


@app.get('/reset_password_link')
async def reset_password_link(my_uuid:str):
    #get id,uuid and genreated time of token via method get_uuid_details
    uuid_details = get_uuid_details((my_uuid))

    if(uuid_details.used == True):
        raise HTTPException(status_code=400, detail='Link already used once')

    mins_passed = ((datetime.now(timezone.utc) - uuid_details.time).seconds)/60
    if(mins_passed > 10):
        raise HTTPException(status_code=401, detail = 'More than 10 minutes have passed')
    
    return {'message': 'Hello', 'my_uuid':my_uuid, 'user_id': uuid_details.id}


@app.post('/reset_password_link')
async def reset_password_link(my_uuid:str,ps:PasswordResetSchema):
    #get id,uuid and genreated time of token via method get_uuid_details
    uuid_details = get_uuid_details((my_uuid))

    if(uuid_details.used == True):
        raise HTTPException(status_code=400, detail='Link already used once')

    mins_passed = ((datetime.now(timezone.utc) - uuid_details.time).seconds)/60
    if(mins_passed > 10):
        raise HTTPException(status_code=401, detail = 'More than 10 minutes have passed')
    else:
        new_user = await get_user_by_id(uuid_details.id)
        #get and hash password if both passwords same
        if(ps.password == ps.confirm_password): 
            if(len(ps.password) < 7):
                raise HTTPException(status_code=401, detail = 'Passwords length < 7')
            else:
                new_user.password =  bcrypt.hashpw(ps.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                # #create a ModelUser instance with the details entered #these comments are an alternate way
                # db_user = ModelUser(id = uuid_details.id, email = new_user.email, password = hashed_password.decode('utf-8'), first_name = new_user.first_name, last_name = new_user.last_name, register_time = new_user.register_time)
                # #update the hashed password in the database
                # db_user.password = hashed_password.decode('utf-8')
                # #add/merge the ModelUser object(db_user) to the database

                db.session.merge(new_user)
                db.session.commit()

                #update uuid details
                uuid_details.used = True
                db.session.merge(uuid_details)
                db.session.commit()
                return {'message':'password change sucessful'}    
        else:
            raise HTTPException(status_code=401, detail = 'Passwords are not same')
        # url = app.url_path_for("change_password")
        # response = RedirectResponse(url, my_uuid)
        # return response

@app.post('/change_password')
async def change_password(ps:PasswordChangeSchema, my_email = Depends(auth_handler.auth_wrapper) ):
    """
    To change password  when the user is logged in. Needs PasswordChangeSchema and JWT token as input parameters. 
    Returns sucessful message if success, otherwise raises error 401.
    
    """
    user = await get_user_by_email(my_email)
    # my_id = user.id
    actual_password = user.password.encode('utf-8')

    if(bcrypt.checkpw(ps.current_password.encode('utf-8'), actual_password)):
        if(ps.new_password == ps.confirm_password and len(ps.new_password) > 6 and ps.new_password != ps.current_password):
            user.password =  bcrypt.hashpw(ps.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            #create a ModelUser instance with the details entered
            # db_user = ModelUser(id = my_id, email = user.email, password = hashed_password.decode('utf-8'), first_name = user.first_name, last_name = user.last_name, register_time = user.register_time)
            # #update the hashed password in the database

            # #add/merge the ModelUser object(db_user) to the database
            db.session.merge(user)

            # db.session.query(ModelUser).filter_by(id = my_id).update({ModelUser.password : hashed_password.decode('utf-8')}, synchronize_session = False)
            db.session.commit()
            db.session.close()
            
            return {'message':'password change sucessful'}    
        else:
            raise HTTPException(status_code=401, detail = 'Passwords must be same and of length greater than 6 and must not be the same as old password ')
    else:
        raise HTTPException(status_code=401, detail = 'Please enter correct current password')


@app.post('/delete_user')
async def delete_user(my_id:int):
     db.session.query(ModelUser).filter_by(id = my_id).delete()
     db.session.commit()
     return {'message': 'deleted'}



#create a new node
@app.post('/create_node')
async def create_node(node:NodeSchema):
    #use of path??

    #check if the "type" of node is actually present in the nodetype table
    prop = db.session.query(NodeType).filter(NodeType.type == node.type).first()
    #if not, return message
    if(prop == None):
        return {"message": "incorrect type field"}
    
    #make a dict which will take only the relevant key-value pairs according to the type of node
    prop_dict = {k: v for k, v in node.properties.items() if k in prop.params.keys()}

    if (len(prop_dict) != len(prop.params.keys())):#necessary fields not filled
        return {"message" : "please enter all fields"}
    if "" in node.dict().values( ) or "" in prop_dict.values(): #For Empty entries.
        return {"message" : "please leave no field empty"}
    
    if "value" in prop_dict.keys() and node.type == "button": # for json in button
            prop_value_json = json.loads(prop_dict['value'])
            if(len(prop_value_json.keys( )) == 0 ):
                return {"message" : "please fill all fields"}
            else:
                for ele in list(prop_value_json.keys()): 
                        if ele not in ["||", "&&", ">", "<", "!"]:
                            return {"message" : "please fill || or && or > or < or ! only"}
                        else:#TODO:complete <=>...validation
                            if "args" in prop_value_json['||']:
                                print(prop_value_json['||']["args"][0]["=="])
                                 #"{\"||\" : {\"args\":[{\"==\":{\"arg1\":\"1\", \"arg2\" : \"2\"}}]}}"
                            # else:
                                # return {"message" : "no args"}
    
    #set unique name
    my_name = secrets.token_hex(4)

    # make a new object of type Node with all the entered details
    new_node = Node(name = my_name, path = my_name, type = node.type, node_type = node.node_type, properties = json.dumps(prop_dict), position = json.dumps(node.position))
    #id,name and path are made private by the "_" before name in schemas.py, so frontend need not enter them.

    db.session.add(new_node)
    db.session.commit()
    return {"message": "success"}


@app.post('/create_connection')
async def create_connection(conn : ConnectionSchema) :
    #if empty, set $success as default
    if conn.sub_node == "" : conn.sub_node = "$success"
    
    if "" in conn.dict().values( ):
        return {"message" : "please leave no field empty"}  

    #set my_name variable which will later be used to set the name
    my_name = "c_" + conn.source_node + "_" + conn.sub_node + "-" + conn.target_node

    if(conn.source_node == conn.target_node):
        return {"message" : "Source and Target node cannot be the same"}

    #if the (source_node's + subnode's) connection exists somewhere, update other variables only. Else make a new entry
    if(db.session.query(Connections).filter_by(source_node = conn.source_node).filter_by(sub_node = conn.sub_node).first() is not None):
        db.session.query(Connections).filter(Connections.source_node == conn.source_node).filter(Connections.sub_node == conn.sub_node).\
        update({'target_node':conn.target_node, 'name' : my_name})
    else:
        new_conn = Connections(sub_node = conn.sub_node, source_node = conn.source_node, target_node = conn.target_node, name = my_name)
        db.session.add(new_conn)

    db.session.commit()
    return {"message":'success'}


@app.post('/create_custom_field')
async def create_custom_field(cus : CustomFieldSchema):

    #check if type exists in the customfieldtypes table
    prop = db.session.query(CustomFieldTypes).filter(CustomFieldTypes.type == cus.type).first()
    
    if(prop == None):
        return {"message": "incorrect type field"}
    if "" in cus.dict().values( ):
        return {"message" : "please leave no field empty"}  

    #check if type entered and value's datatype matches

    try:
        ip_type = type(literal_eval(cus.value))
        if(cus.type == "number"):
            my_type = str(ip_type).split(" ")[-1][:-1].strip("\'")
            print(my_type)
            if my_type != "int" and my_type != "float":
                return {"please check your number"}
        else:
            raise ValueError
    except (ValueError, SyntaxError):# error occurs when type is string
        if cus.type == "text":
            print("str")
        elif(cus.type == "date"):
            try:
                print("date")
                format = "%Y-%m-%d"
                datetime.strptime(cus.value, format)
            except ValueError:
                return {"message" : "This is the incorrect date string format. It should be YYYY-MM-DD"}
        else:
            return {"message": "type not matching"}


    
    #if name exists then update fields. Else make a new entry    
    if(db.session.query(CustomFields).filter_by(name = cus.name).first() is not None):
        db.session.query(CustomFields).filter(CustomFields.name == cus.name).update({'value':cus.value})
        db.session.commit()
        return {"message":'custom field updated'}
    else:
        new_cus = CustomFields(type = cus.type, name = cus.name, value = cus.value)
        db.session.add(new_cus)
        db.session.commit()
        return {"message":'success'}


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port = 8000)
