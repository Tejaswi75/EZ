import os
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File as FastAPIFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from email_validator import validate_email, EmailNotValidError

# --- CONFIG ---
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# --- DB SETUP ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELS ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_ops = Column(Boolean, default=False)  # True for ops, False for client
    is_verified = Column(Boolean, default=False)
    files = relationship("File", back_populates="uploader")

class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    uploader = relationship("User", back_populates="files")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class DownloadToken(Base):
    __tablename__ = "download_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime)

# --- AUTH ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        user_id = int(user_id)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# --- FASTAPI APP ---
app = FastAPI()
Base.metadata.create_all(bind=engine)

# --- OPS LOGIN ---
@app.post("/operation/login")
def operation_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username, User.is_ops == True).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.is_verified is not True:
        raise HTTPException(status_code=400, detail="Email not verified")
    access_token = create_access_token(data={"sub": user.id, "is_ops": True})
    return {"access_token": access_token, "token_type": "bearer"}

# --- OPS UPLOAD FILE (to be implemented) ---
@app.post("/operation/upload-file")
def operation_upload_file():
    return {"message": "Upload endpoint to be implemented"}

# --- CLIENT SIGNUP ---
@app.post("/client/signup")
def client_signup(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    try:
        validate_email(email)
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    user = User(email=email, hashed_password=hashed_password, is_ops=False, is_verified=False)
    db.add(user)
    db.commit()
    db.refresh(user)
    # Here, generate a verification token (for now, just user id)
    verify_token = create_access_token({"sub": user.id}, expires_delta=timedelta(minutes=30))
    verify_url = f"http://localhost:8000/client/verify-email?token={verify_token}"
    # In real app, send email. Here, just return the URL.
    return {"verify_url": verify_url}

# --- CLIENT EMAIL VERIFY ---
@app.get("/client/verify-email")
def client_verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        user_id = int(user_id)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    setattr(user, 'is_verified', True)
    db.commit()
    return {"message": "Email verified!"}

# --- CLIENT LOGIN ---
@app.post("/client/login")
def client_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username, User.is_ops == False).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.is_verified is not True:
        raise HTTPException(status_code=400, detail="Email not verified")
    access_token = create_access_token(data={"sub": user.id, "is_ops": False})
    return {"access_token": access_token, "token_type": "bearer"}

# --- CLIENT FILE LIST (to be implemented) ---
@app.get("/client/files")
def client_list_files():
    return {"message": "List files endpoint to be implemented"}

# --- CLIENT DOWNLOAD (to be implemented) ---
@app.get("/client/download/{token}")
def client_download_file(token: str):
    return {"message": "Download endpoint to be implemented"}