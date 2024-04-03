from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, Depends, HTTPException, status, Header
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta, date
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session
from typing import List, Optional
from jose import JWTError, jwt

# З'єднання з бд
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:1234@localhost/db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Користувач
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Контакт
class Contact(Base):
    __tablename__ = "contacts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    first_name = Column(String)
    last_name = Column(String)
    email = Column(String, index=True)
    phone_number = Column(String)
    birth_date = Column(DateTime)
    additional_data = Column(String, nullable=True)

app = FastAPI()

# Налаштування JWT 
SECRET_KEY = "7b06c5010a2fd16c8d6f8181fc9e2ad6f82d512f79c7b4d8228a09e501dd1191"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Підключення до бд
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Генерація секрету та хешування паролів
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генератор токенів
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Авторизація через токен
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Оголошення Pydantic моделей 
class ContactBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birth_date: date
    additional_data: str = None

class ContactCreateInput(ContactBase):
    pass

class ContactUpdateInput(ContactBase):
    pass

class ContactResponse(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: str
    phone_number: str
    birth_date: date
    additional_data: str = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    created_at: datetime

    class Config:
        orm_mode = True

class ContactCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    phone_number: str
    birth_date: datetime
    additional_data: Optional[str] = None

class ContactUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone_number: Optional[str] = None
    birth_date: Optional[datetime] = None
    additional_data: Optional[str] = None

# Отримання поточного користувача
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Авторизація користувача
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Зареєструвати нового користувача
@app.post("/users/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already registered")
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Створення нового контакту
@app.post("/contacts/", response_model=ContactResponse, status_code=status.HTTP_201_CREATED)
def create_contact(contact: ContactCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_contact = Contact(**contact.dict(), user_id=current_user.id)
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

# Отримання всіх контактів 
@app.get("/contacts/", response_model=List[ContactResponse])
def read_contacts(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Contact).filter(Contact.user_id == current_user.id).offset(skip).limit(limit).all()

# Отримання одного контакту по ID
@app.get("/contacts/{contact_id}", response_model=ContactResponse)
def read_contact(contact_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return contact

# Оновлення контакту
@app.put("/contacts/{contact_id}", response_model=ContactResponse)
def update_contact(contact_id: int, contact: ContactUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    for key, value in contact.dict().items():
        if value is not None:
            setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

# Видалення контакту
@app.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if db_contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    db.delete(db_contact)
    db.commit()
    return {"message": "Contact deleted successfully"}

# Отримання контактів з наближеними днями народження
@app.get("/contacts/birthday", response_model=List[ContactResponse])
def get_contacts_with_upcoming_birthdays(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    today = datetime.today()
    next_week = today + timedelta(days=7)
    return db.query(Contact).filter(Contact.user_id == current_user.id, Contact.birth_date >= today, Contact.birth_date <= next_week).all()
