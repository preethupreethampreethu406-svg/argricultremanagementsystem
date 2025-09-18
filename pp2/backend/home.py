

"""
AgriRent Backend (single-file FastAPI app)

Requirements (install):
    pip install fastapi uvicorn sqlmodel[sqlite] passlib[bcrypt] python-jose[cryptography] python-multipart pydantic

Run:
    uvicorn app:app --reload

This is a self-contained example for development/demo purposes. It uses SQLite + SQLModel, JWT auth,
basic endpoints for users, equipment, bookings, and a payment-stub. Adapt for production (secure JWT key, HTTPS,
proper payment gateway, migrations, RBAC, input validation, rate limiting, etc.).
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, status, Form, UploadFile, File
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlmodel import Field, SQLModel, create_engine, Session, select
from pydantic import BaseModel

# ---------- Configuration ----------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./agrirent.db")
JWT_SECRET = os.environ.get("JWT_SECRET", "changeme-please-replace")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

# ---------- App & DB ----------
app = FastAPI(title="AgriRent - Backend (Demo)")
engine = create_engine(DATABASE_URL, echo=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- Models ----------
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    hashed_password: str
    is_admin: bool = Field(default=False)
    phone: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Equipment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str
    description: Optional[str] = None
    price_per_day: float = 0.0
    category: Optional[str] = None
    rating: Optional[float] = 5.0
    metadata: Optional[str] = None  # JSON string in simple demo
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Booking(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    equipment_id: int = Field(foreign_key="equipment.id")
    start_date: datetime
    end_date: datetime
    farm_location: Optional[str] = None
    special_requirements: Optional[str] = None
    status: str = Field(default="pending")  # pending, confirmed, cancelled, completed
    created_at: datetime = Field(default_factory=datetime.utcnow)

# ---------- Pydantic Schemas ----------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    phone: Optional[str] = None

class UserRead(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    phone: Optional[str]
    is_admin: bool

class EquipmentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price_per_day: float
    category: Optional[str] = None

class BookingCreate(BaseModel):
    equipment_id: int
    start_date: datetime
    end_date: datetime
    farm_location: Optional[str] = None
    special_requirements: Optional[str] = None

# ---------- Utility functions ----------
def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(lambda: None), session: Session = Depends(get_session)):
    # This dependency will be replaced by OAuth2 scheme below in endpoints
    raise NotImplementedError

# For simplicity we'll implement a small helper to decode token given a header token string

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise JWTError()
        return int(user_id)
    except JWTError:
        return None

# ---------- Auth endpoints (register/login) ----------
@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    # Create a demo admin if none exists
    with Session(engine) as session:
        q = select(User).where(User.email == "admin@agrirent.com")
        admin = session.exec(q).first()
        if not admin:
            admin_user = User(
                email="admin@agrirent.com",
                full_name="Admin",
                hashed_password=get_password_hash("admin123"),
                is_admin=True,
            )
            session.add(admin_user)
            session.commit()

@app.post("/auth/register", response_model=UserRead)
def register(user_in: UserCreate, session: Session = Depends(get_session)):
    q = select(User).where(User.email == user_in.email)
    exists = session.exec(q).first()
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        phone=user_in.phone,
        hashed_password=get_password_hash(user_in.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return UserRead(**user.dict())

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    q = select(User).where(User.email == form_data.username)
    user = session.exec(q).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": str(user.id)})
    return Token(access_token=access_token)

# Dependency to obtain current user from Authorization header Bearer token
from fastapi.security import OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

async def get_current_user_from_token(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    user_id = decode_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    q = select(User).where(User.id == user_id)
    user = session.exec(q).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_admin_user(current_user: User = Depends(get_current_user_from_token)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

# ---------- Equipment endpoints ----------
@app.post("/equipment", response_model=EquipmentCreate, status_code=201)
def create_equipment(e: EquipmentCreate, admin: User = Depends(get_admin_user), session: Session = Depends(get_session)):
    eq = Equipment(
        title=e.title,
        description=e.description,
        price_per_day=e.price_per_day,
        category=e.category,
    )
    session.add(eq)
    session.commit()
    session.refresh(eq)
    return EquipmentCreate(**eq.dict())

@app.get("/equipment", response_model=List[EquipmentCreate])
def list_equipment(skip: int = 0, limit: int = 50, session: Session = Depends(get_session)):
    q = select(Equipment).offset(skip).limit(limit)
    items = session.exec(q).all()
    return [EquipmentCreate(**item.dict()) for item in items]

@app.get("/equipment/{equipment_id}")
def get_equipment(equipment_id: int, session: Session = Depends(get_session)):
    q = select(Equipment).where(Equipment.id == equipment_id)
    item = session.exec(q).first()
    if not item:
        raise HTTPException(status_code=404, detail="Equipment not found")
    return item

# ---------- Booking endpoints ----------
@app.post("/bookings", status_code=201)
def create_booking(b: BookingCreate, current_user: User = Depends(get_current_user_from_token), session: Session = Depends(get_session)):
    # Basic availability check: ensure no overlapping confirmed bookings for same equipment
    q = select(Booking).where(
        (Booking.equipment_id == b.equipment_id)
        & (Booking.status == "confirmed")
        & (Booking.end_date >= b.start_date)
        & (Booking.start_date <= b.end_date)
    )
    overlap = session.exec(q).first()
    if overlap:
        raise HTTPException(status_code=400, detail="Equipment not available for the selected dates")
    booking = Booking(
        user_id=current_user.id,
        equipment_id=b.equipment_id,
        start_date=b.start_date,
        end_date=b.end_date,
        farm_location=b.farm_location,
        special_requirements=b.special_requirements,
        status="pending",
    )
    session.add(booking)
    session.commit()
    session.refresh(booking)
    return {"message": "Booking request created", "booking_id": booking.id}

@app.get("/bookings/me")
def my_bookings(current_user: User = Depends(get_current_user_from_token), session: Session = Depends(get_session)):
    q = select(Booking).where(Booking.user_id == current_user.id).order_by(Booking.created_at.desc())
    items = session.exec(q).all()
    return items

@app.get("/bookings", response_model=List[Booking])
def all_bookings(admin: User = Depends(get_admin_user), session: Session = Depends(get_session)):
    q = select(Booking).order_by(Booking.created_at.desc())
    return session.exec(q).all()

@app.post("/bookings/{booking_id}/confirm")
def confirm_booking(booking_id: int, admin: User = Depends(get_admin_user), session: Session = Depends(get_session)):
    q = select(Booking).where(Booking.id == booking_id)
    booking = session.exec(q).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    booking.status = "confirmed"
    session.add(booking)
    session.commit()
    return {"message": "Booking confirmed"}

@app.post("/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: int, current_user: User = Depends(get_current_user_from_token), session: Session = Depends(get_session)):
    q = select(Booking).where(Booking.id == booking_id)
    booking = session.exec(q).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    # Allow admin or owner to cancel
    if booking.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to cancel this booking")
    booking.status = "cancelled"
    session.add(booking)
    session.commit()
    return {"message": "Booking cancelled"}

# ---------- Simple Payment Stub ----------
class PaymentRequest(BaseModel):
    booking_id: int
    payment_method: str  # e.g., "card", "upi", "cod" etc.

@app.post("/payments/charge")
def charge(payment: PaymentRequest, current_user: User = Depends(get_current_user_from_token), session: Session = Depends(get_session)):
    # In production, integrate with Stripe/PayPal/Razorpay. This is a demo stub.
    q = select(Booking).where(Booking.id == payment.booking_id)
    booking = session.exec(q).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    if booking.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not allowed to pay for this booking")
    # compute amount (days * price)
    qeq = select(Equipment).where(Equipment.id == booking.equipment_id)
    equipment = session.exec(qeq).first()
    days = max(1, (booking.end_date - booking.start_date).days or 1)
    amount = days * (equipment.price_per_day if equipment else 0)
    # pretend we charged and confirm the booking
    booking.status = "confirmed"
    session.add(booking)
    session.commit()
    return {"message": "Payment processed (demo)", "amount": amount}

# ---------- Utility endpoints (user profile) ----------
@app.get("/me", response_model=UserRead)
def read_profile(current_user: User = Depends(get_current_user_from_token)):
    return UserRead(**current_user.dict())

# ---------- File upload example for equipment images (simple) ----------
@app.post("/equipment/{equipment_id}/upload-image")
def upload_equipment_image(equipment_id: int, file: UploadFile = File(...), admin: User = Depends(get_admin_user), session: Session = Depends(get_session)):
    # Save file to ./uploads/<equipment_id>_<filename>
    uploads_dir = os.path.join(os.getcwd(), "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    safe_name = f"{equipment_id}_{int(datetime.utcnow().timestamp())}_{file.filename}"
    path = os.path.join(uploads_dir, safe_name)
    with open(path, "wb") as f:
        f.write(file.file.read())
    return {"message": "Uploaded", "path": path}

# ---------- Health check ----------
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow()}

# ---------- Main ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
