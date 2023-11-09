from fastapi import FastAPI, Depends, HTTPException, Security
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import random
import string
from bson import ObjectId
from fastapi import HTTPException
import re 
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



app = FastAPI()

# JWT Authentication settings
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# MongoDB connection setup
database_url = "mongodb://mongodb:27017"
client = AsyncIOMotorClient(database_url)
db = client["carparking_db"]

# Password Hashing
password_hash = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return password_hash.hash(password)

def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Schema for OAuth2 Password Request Form
class Token(BaseModel):
    access_token: str
    token_type: str

# Function to verify the token
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# /token endpoint for obtaining an access token
@app.post("/token", response_model=Token)
async def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    if user is None or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}


# Define_amount the function to verify and decode JWT tokens
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# User Model for registration
class UserSignin(BaseModel):
    username: str
    password: str
    address: str
    isAdmin: bool = False


class AdminSignup(BaseModel):
    username: str
    password: str

# Landlord Signup Model
class LandlordSignup(BaseModel):
    username: str
    password: str
    address: str

# Car Owner Signup Model
class CarOwnerSignup(BaseModel):
    pcn: str
    car_number: str

# Common function to get the current date in the "yearmonthdate" format
def get_current_date():
    return datetime.today().strftime('%Y%m%d')

# Admin Signup Route
@app.post("/signup/admin", tags=["auth"])
async def admin_signup(admin: AdminSignup):
    existing_user = await db.users.find_one({"username": admin.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already registered")

    user_dict = admin.dict()
    user_dict["password"] = hash_password(user_dict["password"])
    user_dict["isAdmin"] = True  # Set isAdmin to True for admin signup
    user_dict["account_creation_date"] = get_current_date()
    result = await db.users.insert_one(user_dict)
    return {"message": "Admin registered successfully"}

# Landlord Model for registration (without isLandlord field and account_creation_date)
class LandlordSignup(BaseModel):
    username: str
    password: str
    address: str


# Landlord Signup endpoint
@app.post("/signup/landlord", tags=["auth"])
async def landlord_signup(user: LandlordSignup):
    # Set isLandlord to True by default
    user_dict = user.dict()
    user_dict["isLandlord"] = True

    # Check for existing landlord user with the same username (optional)
    existing_user = await db.users.find_one({"username": user.username, "isLandlord": True})
    if existing_user:
        raise HTTPException(status_code=400, detail="Landlord user already registered")

    # Hash the password, set the account creation date to the current date, and save the user
    user_dict["password"] = hash_password(user_dict["password"])
    user_dict["account_creation_date"] = datetime.today().strftime('%Y%m%d')
    
    result = await db.users.insert_one(user_dict)
    
    return {"message": "Landlord user registered successfully"}

# User Model for login
class UserLogin(BaseModel):
    username: str
    password: str

# Login endpoint for admin users
@app.post("/login/admin", tags=["auth"])
async def admin_login(user: UserLogin):
    stored_user = await db.users.find_one({"username": user.username, "isAdmin": True})

    if stored_user is None or not verify_password(user.password, stored_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

# Login endpoint for landlord users
@app.post("/login/landlord", tags=["auth"])
async def landlord_login(user: UserLogin):
    stored_user = await db.users.find_one({"username": user.username, "isLandlord": True})

    if stored_user is None or not verify_password(user.password, stored_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

# Car Owner Model for login
class CarOwnerLogin(BaseModel):
    pcn: str
    car_number: str

# Car Owner Login endpoint
@app.post("/login/carowner", tags=["auth"])
async def carowner_login(user: CarOwnerLogin):
    pcn = user.pcn
    car_number = user.car_number

    # Check if there is a document in the complaints collection with the provided PCN and car number
    complaints_collection = db["complaints"]
    complaint = await complaints_collection.find_one({"pcn": pcn, "car_number": car_number})
    
    if not complaint:
        raise HTTPException(status_code=400, detail="Invalid PCN or car number")


    # If the PCN and car number are valid, you can generate an access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": pcn}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}


# Logout endpoint
@app.post("/logout", tags=["auth"])
async def logout(token: str):
    if await revoked_tokens.find_one({"token": token}):
        raise HTTPException(status_code=400, detail="Token is already revoked")
    revoked_tokens.insert_one({"token": token})
    return {"message": "Logout successful"}

# User Model for complaints
class ComplaintCreate(BaseModel):
    car_number: str
    date_of_offense: str
    date_of_complaint: str
    pcn: str
    user_name: str

# Function to create revoked tokens collection
async def create_revoked_tokens_collection():
    if "revoked_tokens" not in await db.list_collection_names():
        await db.create_collection("revoked_tokens")

# Initialize the revoked_tokens collection
revoked_tokens = db["revoked_tokens"]

# Endpoint to add a complaint
def get_current_username(token: str = Security(oauth2_scheme)):
    credentials = verify_token(token)
    return credentials.get("sub")

async def generate_random_pcn():
    pcn = 'PCN' + ''.join(random.choice(string.digits) for _ in range(9))
    exists = await db["complaints"].find_one({"pcn": pcn})
    if not exists:
        return pcn
    else:
        return await generate_random_pcn()  # Return the result of the recursive call


# Updated add_complaint route
@app.post("/add_complaint", tags=["complaint"])
async def add_complaint(
    car_number: str,
    date_of_offense: str,
    picture: str,
    message_by_landlord: str,
    current_user: str = Depends(get_current_username)
):
    # Validate date_of_offense format
    if not re.match(r'^\d{8}$', date_of_offense):
        raise HTTPException(status_code=400, detail="Invalid date format. Use the format 'yearmonthdate' (e.g., '20231104').")
    
    pcn = await generate_random_pcn()  # Await the coroutine here
    date_of_complaint = datetime.today().strftime('%Y%m%d')
    date_diff = (datetime.strptime(date_of_complaint, '%Y%m%d') - datetime.strptime(date_of_offense, '%Y%m%d')).days
    if date_diff < 14:
        complaint_status = "stage1"
        fine_amount = 60
    elif date_diff >= 14 and date_diff < 28:
        complaint_status = "stage2"
        fine_amount = 100
    elif date_diff >= 28 and date_diff < 42:
        complaint_status = "stage3"
        fine_amount = 170
    else:
        complaint_status = "on court"
        fine_amount = None

    complaint_dict = {
        "_id": str(ObjectId()),  # Generate a new ObjectId and convert it to a string
        "car_number": car_number,
        "date_of_offense": date_of_offense,
        "date_of_complaint": date_of_complaint,
        "username": current_user,
        "pcn": pcn,
        "complaint_status": complaint_status,
        "fine_amount": fine_amount,
        "car_number_plate_picture": picture,
        "message_by_landlord": message_by_landlord,
    }

    complaints_collection = db["complaints"]
    result = await complaints_collection.insert_one(complaint_dict)
    if result:
        return {"message": "Complaint added successfully", "pcn": complaint_dict["pcn"]}
    else:
        return {"message": "Failed to add complaint"}


# Update Complaint Model
class UpdateComplaint(BaseModel):
    car_owner_name: str
    car_owner_email: str
    car_number_plate_picture: str
    car_owner_type: str
    payment_done: bool = False
    ticket: str = "open"
    # complaint_status: str = 'step1'

@app.put("/complaint/{complaint_id}", tags=["complaint"])
async def update_complaint(
    complaint_id: str, 
    complaint_data: UpdateComplaint, 
    current_user: str = Depends(get_current_username)
):
    # Check if the current user is an admin
    user_collection = db["users"]
    current_user_data = await user_collection.find_one({"username": current_user})

    if not current_user_data or not current_user_data.get("isAdmin", False):
        raise HTTPException(status_code=403, detail="Only administrators can update complaints")

    complaints_collection = db["complaints"]
    existing_complaint = await complaints_collection.find_one({"_id": complaint_id})

    if not existing_complaint:
        raise HTTPException(status_code=404, detail="Complaint not found")

    updated_data = complaint_data.dict(exclude_unset=True)  # Exclude unset values (None)

    # Handle the car number plate picture update (e.g., store the URL or file path in the database)
    if "car_number_plate_picture" in updated_data:
        existing_complaint["car_number_plate_picture"] = updated_data["car_number_plate_picture"]
    
    if updated_data:
        update_result = await complaints_collection.update_one(
            {"_id": complaint_id},
            {"$set": updated_data}
        )

        if update_result.modified_count == 1:
            return {"message": "Complaint updated successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to update complaint")
    else:
        return {"message": "No changes to update"}


# Function to send an email
def send_email(to_email, pcn, domain="", car_no=None):
    # Your email configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_username = "singha1993subhajit@gmail.com"
    smtp_password = "zpbo hvtw clfn tvju"
    sender_email = "singha1993subhajit@gmail.com"

    # Create a message
    subject = "Rule violation alert"
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject

    body = f"You have violated some rules related to car parking, login to {domain} with Your Car No.{car_no} and  PCN: {pcn}"
    message.attach(MIMEText(body, "plain"))

    # Connect to the SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(sender_email, to_email, message.as_string())

# Route to send an email for a specific complaint ID
@app.post("/send_email/{complaint_id}", tags=["complaint"])
async def send_email_for_complaint(complaint_id: str, current_user: str = Depends(get_current_username)):
    # Check if the current user is an admin
    user_collection = db["users"]
    current_user_data = await user_collection.find_one({"username": current_user})

    if not current_user_data or not current_user_data.get("isAdmin", False):
        raise HTTPException(status_code=403, detail="Only administrators can send emails for complaints")

    complaints_collection = db["complaints"]
    complaint = await complaints_collection.find_one({"_id": complaint_id})

    if not complaint:
        raise HTTPException(status_code=404, detail="Complaint not found")

    car_owner_email = complaint.get("car_owner_email")
    pcn = complaint.get("pcn")
    car_no = complaint.get("car_number")

    if not car_owner_email:
        raise HTTPException(status_code=400, detail="Car owner email not found for this complaint")

    # Send the email
    send_email(car_owner_email, pcn, domain="https://api.ssdevelopment.online/docs", car_no=car_no)

    return {"message": "Email sent successfully"}



# Car Owner Dependency
def get_current_car_owner(token: str = Security(oauth2_scheme)):
    credentials = verify_token(token)
    if not credentials:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return credentials.get("sub")

# Car Owner Model for complaint retrieval
class CarOwnerComplaint(BaseModel):
    pcn: str
    car_number: str

# Car Owner Complaint Route
@app.get("/complaint/{pcn}", tags=["complaint"])
async def get_complaint_by_pcn(pcn: str, car_number: str, current_user: str = Depends(get_current_car_owner)):
    complaints_collection = db["complaints"]
    complaint = await complaints_collection.find_one({"pcn": pcn, "car_number": car_number})
    if complaint:
        result = {
            "_id": str(complaint["_id"]),
            "car_number": complaint["car_number"],
            "date_of_offense": complaint["date_of_offense"],
            "date_of_complaint": complaint["date_of_complaint"],
            "username": complaint["username"],
            "pcn": complaint["pcn"],
            "car_owner_name": complaint["car_owner_name"],
            "car_owner_email": complaint["car_owner_email"],
        }
        return result
    else:
        raise HTTPException(status_code=404, detail="Complaint not found")




# Get All Complaints by Username
@app.get("/complaints", tags=["complaint"])
async def get_complaints_by_username(current_user: str = Depends(get_current_username)):
    complaints_collection = db["complaints"]
    complaints = await complaints_collection.find({"username": current_user}).to_list(None)
    return complaints

# Get All Complaints Route for Admin Users
@app.get("/complaints/admin", tags=["complaint"])
async def get_all_complaints_for_admin(current_user: str = Depends(get_current_username)):
    user = await db.users.find_one({"username": current_user})
    
    if user and user.get("isAdmin", False):  # Check if the user is an admin
        complaints_collection = db["complaints"]
        complaints = await complaints_collection.find({}).to_list(None)
        return complaints
    else:
        raise HTTPException(status_code=403, detail="You do not have permission to access this data")
    



class AppealModel(BaseModel):
    appeal_message: str

# Route to add an appeal to a complaint without authentication
@app.post("/appeal/{complaint_id}", tags=["appeal"])
async def add_appeal(
    complaint_id: str,
    appeal_data: AppealModel,
    current_user: str = Depends(get_current_car_owner)
):
    complaints_collection = db["complaints"]
    existing_complaint = await complaints_collection.find_one({"_id": complaint_id})

    if not existing_complaint:
        raise HTTPException(status_code=404, detail="Complaint not found")

    # Update the complaint with the appeal data
    appeal_message = appeal_data.appeal_message
    await complaints_collection.update_one(
        {"_id": complaint_id},
        {"$set": {
            "appeal": True,
            "appeal_message": appeal_message
        }}
    )
    
    return {"message": "Appeal added successfully"}

# Route to change the payment status to True for a complaint
@app.put("/payment_status/{complaint_id}", tags=["payment"])
async def change_payment_status(
    complaint_id: str, current_user: str = Depends(get_current_car_owner)
):
    complaints_collection = db["complaints"]
    existing_complaint = await complaints_collection.find_one({"_id": complaint_id})

    if not existing_complaint:
        raise HTTPException(status_code=404, detail="Complaint not found")

    # Update the complaint's payment status to True
    await complaints_collection.update_one(
        {"_id": complaint_id},
        {"$set": {"payment_done": True}}
    )

    return {"message": "Payment status changed to True for the complaint"}

# Route to change the ticket status to "closed" for a complaint (only admins)
@app.put("/close_ticket/{complaint_id}", tags=["Complained Ticket"])
async def close_ticket(
    complaint_id: str, 
    current_user: str = Depends(get_current_username)
):
    # Check if the current user is an admin
    user_collection = db["users"]
    current_user_data = await user_collection.find_one({"username": current_user})

    if not current_user_data or not current_user_data.get("isAdmin", False):
        raise HTTPException(status_code=403, detail="Only administrators can close tickets")

    complaints_collection = db["complaints"]
    existing_complaint = await complaints_collection.find_one({"_id": complaint_id})

    if not existing_complaint:
        raise HTTPException(status_code=404, detail="Complaint not found")

    # Update the complaint's status to "closed"
    await complaints_collection.update_one(
        {"_id": complaint_id},
        {"$set": {"ticket": "closed"}}
    )

    return {"message": "Ticket status changed to 'closed' for the complaint"}


if __name__ == "__main__":
    import uvicorn
    import asyncio
    asyncio.run(create_revoked_tokens_collection())
    uvicorn.run(app, host="0.0.0.0", port=8000)
