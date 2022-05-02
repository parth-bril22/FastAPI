from xmlrpc.client import Boolean
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, BOOLEAN
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
Base  = declarative_base()

class User(Base):
    __tablename__ = 'login'
    id = Column(Integer, primary_key = True)
    email = Column(String)
    password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    register_time = Column(DateTime)
    pwd_token = relationship("Password_tokens", back_populates = "user", uselist = False, cascade = "all, delete", passive_deletes = True)


class Password_tokens(Base):
    __tablename__ = 'password_tokens'
    id = Column(Integer, ForeignKey("login.id", ondelete = "CASCADE"), primary_key = True)
    uuid = Column(String)
    time = Column(DateTime)
    used = Column(BOOLEAN)
    user = relationship("User", back_populates = "pwd_token")

#----------!!!!!!!!!!!!!!!!!!-----------------------------
# import copy
# doc.config = copy.deepcopy(doc.config)

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSON


# Base  = declarative_base()

class Node(Base):
    __tablename__ = 'node'
    id = Column(Integer, primary_key = True)
    name = Column(String)
    path = Column(String)
    node_type = Column(String)
    properties = Column(JSON)#but input will be as string/dict
    position = Column(JSON)#string/dict
    type = Column(String, ForeignKey("node_type.type", ondelete = "NO ACTION"))
    node_conn = relationship("NodeType", back_populates = "node_type_conn")

class NodeType(Base):
    __tablename__ = 'node_type'
    id = Column(Integer, primary_key = True)
    type = Column(String, unique = True)
    params = Column(JSON)
    node_type_conn = relationship("Node", back_populates = "node_conn")


class Connections(Base):
    __tablename__ = 'connections'
    id = Column(Integer, primary_key = True)
    name = Column(String)
    source_node = Column(String)
    target_node = Column(String)
    sub_node = Column(String)

class CustomFields(Base):
    __tablename__ = 'custom_fields'
    id = Column(Integer, primary_key = True)
    name = Column(String)
    value = Column(String)
    type = Column(String, ForeignKey("custom_field_types.type", ondelete = "NO ACTION"))
    custom_field_conn = relationship("CustomFieldTypes", back_populates = "custom_field_type_conn")

class CustomFieldTypes(Base):
    __tablename__ = 'custom_field_types'
    type = Column(String, primary_key =True)
    datatype = Column(String)
    custom_field_type_conn = relationship("CustomFields", back_populates = "custom_field_conn")


class Diagram(Base):
    __tablename__ = 'diagram'
    id = Column(String, primary_key = True)
    name = Column(String)



