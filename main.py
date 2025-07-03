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
from uuid import uuid4
from fastapi.responses import FileResponse

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
        print("Decoded JWT payload:", payload)  # Debug print
        user_id = payload.get("sub")
        if user_id is None:
            print("No sub in payload")
            raise credentials_exception
        user_id = int(user_id)
    except JWTError as e:
        print("JWTError:", e)
        raise credentials_exception
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        print("No user found for id", user_id)
        raise credentials_exception
    return user

app = FastAPI()
Base.metadata.create_all(bind=engine)

@app.post("/operation/login")
def operation_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username, User.is_ops == True).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.is_verified is not True:
        raise HTTPException(status_code=400, detail="Email not verified")
    access_token = create_access_token(data={"sub": str(user.id), "is_ops": True})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/operation/upload-file")
def operation_upload_file(
    file: UploadFile = FastAPIFile(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    if current_user.is_ops is not True:
        raise HTTPException(status_code=403, detail="Only ops users can upload files.")

    allowed_exts = {".pptx", ".docx", ".xlsx"}
    filename = file.filename
    if filename is None:
        raise HTTPException(status_code=400, detail="Filename is required.")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail="Invalid file type. Only pptx, docx, xlsx allowed.")

    save_path = os.path.join(UPLOAD_DIR, filename)
    with open(save_path, "wb") as buffer:
        buffer.write(file.file.read())

    db_file = File(filename=filename, uploader_id=current_user.id)
    db.add(db_file)
    db.commit()
    db.refresh(db_file)

    return {"message": "File uploaded successfully", "file_id": db_file.id, "filename": filename}


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

    verify_token = create_access_token({"sub": str(user.id)}, expires_delta=timedelta(minutes=30))
    verify_url = f"http://localhost:8000/client/verify-email?token={verify_token}"
    # In real app, send email. Here, just return the URL.
    return {"verify_url": verify_url}

@app.get("/client/verify-email")
def client_verify_email(token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        user_id = int(user_id)
    except JWTError as e:
        print(f"JWTError: {e}")  # <--- This will print the real error in your server log
        raise HTTPException(status_code=400, detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    setattr(user, 'is_verified', True)
    db.commit()
    return {"message": "Email verified!"}

@app.post("/client/login")
def client_login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username, User.is_ops == False).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.is_verified is not True:
        raise HTTPException(status_code=400, detail="Email not verified")
    access_token = create_access_token(data={"sub": user.id, "is_ops": False})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/client/files")
def client_list_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    is_ops = current_user.is_ops is True if not hasattr(type(current_user), 'is_ops') or not isinstance(getattr(type(current_user), 'is_ops'), property) else False
    is_verified = current_user.is_verified is True if not hasattr(type(current_user), 'is_verified') or not isinstance(getattr(type(current_user), 'is_verified'), property) else False
    if is_ops or not is_verified:
        raise HTTPException(status_code=403, detail="Only verified client users can list files.")
    files = db.query(File).all()
    return [{"file_id": f.id, "filename": f.filename, "uploaded_at": f.uploaded_at.isoformat()} for f in files]

@app.post("/client/request-download/{file_id}")
def request_download(file_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    is_ops = current_user.is_ops is True if not hasattr(type(current_user), 'is_ops') or not isinstance(getattr(type(current_user), 'is_ops'), property) else False
    is_verified = current_user.is_verified is True if not hasattr(type(current_user), 'is_verified') or not isinstance(getattr(type(current_user), 'is_verified'), property) else False
    if is_ops or not is_verified:
        raise HTTPException(status_code=403, detail="Only verified client users can request downloads.")
    file = db.query(File).filter(File.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    token = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    db_token = DownloadToken(token=token, file_id=file.id, user_id=current_user.id, expires_at=expires_at)
    db.add(db_token)
    db.commit()
    download_url = f"http://localhost:8000/client/download/{token}"
    return {"download_url": download_url, "expires_at": expires_at.isoformat()}

@app.get("/client/download/{token}")
def client_download_file(token: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_token = db.query(DownloadToken).filter(DownloadToken.token == token).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Invalid or expired download token.")

    is_ops = current_user.is_ops is True if not hasattr(type(current_user), 'is_ops') or not isinstance(getattr(type(current_user), 'is_ops'), property) else False
    is_verified = current_user.is_verified is True if not hasattr(type(current_user), 'is_verified') or not isinstance(getattr(type(current_user), 'is_verified'), property) else False
    if is_ops or not is_verified:
        raise HTTPException(status_code=403, detail="Only verified client users can download files.")
    if db_token.__dict__['user_id'] != current_user.__dict__['id']:
        raise HTTPException(status_code=403, detail="This download link is not for you.")
    if db_token.__dict__['expires_at'] < datetime.utcnow():
        raise HTTPException(status_code=403, detail="Download link expired.")
    file = db.query(File).filter(File.id == db_token.file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found.")
    filename = getattr(file, 'filename', None)
    if not isinstance(filename, str) or not filename:
        raise HTTPException(status_code=404, detail="File has no filename.")
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server.")
    return FileResponse(file_path, filename=filename, media_type="application/octet-stream")

@app.post("/operation/create-ops-user")
def create_ops_user(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    user = User(email=email, hashed_password=hashed_password, is_ops=True, is_verified=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Ops user created", "user_id": user.id}