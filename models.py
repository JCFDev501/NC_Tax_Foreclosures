import enum
import uuid
from flask_login import UserMixin
from marshmallow import fields
from marshmallow_sqlalchemy.fields import Nested
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import JSON, ARRAY, func
from werkzeug.security import generate_password_hash, check_password_hash

from config import db, app, ma
from county_manager import CountyManager


class DevTokenStatus(enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    # Add more statuses as neededs


class FeatureStatus(enum.Enum):
    incomplete = "incomplete"
    incomplete_expired = "incomplete_expired"
    trialing = "trialing"
    active = "active"
    past_due = "past_due"
    canceled = "canceled"
    unpaid = "unpaid"
    paused = "paused"


class User(db.Model, UserMixin):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)
    admin_password = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # One-to-One relationship with DeveloperAccount
    developer_account = db.relationship('DeveloperAccount', backref='user', uselist=False, cascade="all, delete")

    # One-to-One relationship with PaymentAccount
    payment_account = db.relationship('PaymentAccount', backref='user', uselist=False, cascade="all, delete")

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, password={self.password}, name={self.name}, role={self.role}, created_at={self.created_at})>"


class DeveloperAccount(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=False)  # Foreign key to User
    is_enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # One-to-Many relationship with DeveloperToken
    developer_tokens = db.relationship('DeveloperToken', backref='developer_account', cascade="all, delete")

    def __repr__(self):
        return f"<User(id={self.id}, user_id={self.user_id}, created_at={self.created_at}, developer_tokens={self.developer_tokens})>"


class DeveloperToken(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    developer_account_id = db.Column(UUID(as_uuid=True), db.ForeignKey("developer_account.id"), nullable=False)  #
    # Foreign key to DeveloperAccount
    title = db.Column(db.String(255), nullable=False)
    urls = db.Column(ARRAY(db.String), nullable=False)
    status = db.Column(db.Enum(DevTokenStatus), nullable=False, default=DevTokenStatus.INACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return (f"<DeveloperToken(id={self.id}, developer_account_id={self.developer_account_id}, title={self.title}, "
                f"urls={self.urls}, status={self.status}, created_at={self.created_at})>")


class PaymentAccount(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("user.id"), nullable=False)  # Foreign key to User
    stripe_customer_id = db.Column(db.String(255), nullable=False)

    # One-to-many relationship with UserPurchaseStatus
    user_purchase_statuses = db.relationship('UserPurchaseStatus', backref='payment_account', lazy=True)


class UserPurchaseStatus(db.Model):
    id = db.Column(db.String(255), primary_key=True, nullable=False)
    payment_account_id = db.Column(UUID(as_uuid=True), db.ForeignKey("payment_account.id"),
                                   nullable=False)  # Foreign key to PaymentAccount
    feature_type = db.Column(db.String(255), nullable=False)
    feature_status = db.Column(db.Enum(FeatureStatus), nullable=False)


class TaxForeclosure(db.Model):
    id = db.Column(db.String(80), primary_key=True)
    case_number = db.Column(db.String(80), unique=False, nullable=False)
    parcel_identification = db.Column(db.String(80), unique=False, nullable=True)
    reid_number = db.Column(db.String(80), unique=False, nullable=True)
    highest_bid = db.Column(db.Float, unique=False, nullable=True)
    status = db.Column(db.String(80), unique=False, nullable=True)
    county = db.Column(db.String(80), nullable=False)
    foreclosure_date = db.Column(db.Date, nullable=True)
    upset_bid_date = db.Column(db.Date, nullable=True)
    data = db.Column(db.Text, nullable=False)
    date_last_updated = db.Column(db.DateTime, nullable=False, default=datetime.now(), onupdate=datetime.now())
    spider = db.Column(db.String(80), nullable=False, default='')  # Spider that scraped the data

    # Store tags as a JSON array
    tags = db.Column(JSONB, nullable=True)

    # One-to-One relationship with AdditionalTaxForeclosureData
    additional_data = db.relationship('AdditionalTaxForeclosureData', backref='tax_foreclosure', uselist=False, cascade="all, delete")


    # Method to set tags as a list
    def set_tags(self, tags_list):
        """
        Sets the tags for this TaxForeclosure record.
        Accepts a list of strings and stores it in the JSON column.
        """
        self.tags = list(set(tags_list)) if tags_list else []

    # Method to retrieve the tags as a list
    def get_tags(self):
        """
        Returns the tags as a list, or an empty list if no tags are set.
        """
        return self.tags if self.tags else []

    def __repr__(self):
        return (
            f"<TaxForeclosure(id={self.id}, case_number={self.case_number}, parcel_identification={self.parcel_identification}, reid_number={self.reid_number}, highest_bid={self.highest_bid},"
            f" status={self.status} county={self.county}, foreclosure_date={self.foreclosure_date}, data={self.data}, date_lasted_updated={self.date_lasted_updated})>")


class AdditionalTaxForeclosureData(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    tax_foreclosure_id = db.Column(db.String(255), db.ForeignKey("tax_foreclosure.id"), nullable=False)
    lot_size = db.Column(db.String(80), unique=False, nullable=True)
    assessed_value = db.Column(db.Float, unique=False, nullable=True)
    delinquent = db.Column(db.Float, unique=False, nullable=True)
    zoning_code = db.Column(db.String(80), unique=False, nullable=True)
    has_water = db.Column(db.Boolean, unique=False, nullable=True)
    has_electric = db.Column(db.Boolean, unique=False, nullable=True)
    has_sewage = db.Column(db.Boolean, unique=False, nullable=True)
    legal_description = db.Column(db.Text, nullable=True)
    structure = db.Column(db.String(80), nullable=True)
    year_built = db.Column(db.String(80), nullable=True)
    condition = db.Column(ARRAY(db.String), nullable=True)
    occupancy = db.Column(db.String(80), nullable=True)
    street = db.Column(db.String(80), nullable=True)
    city = db.Column(db.String(80), nullable=True)
    state = db.Column(db.String(80), nullable=True)
    zip = db.Column(db.String(80), nullable=True)
    geometry = db.Column(JSON, nullable=True)
    date_last_updated = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return (
            f"<AdditionalTaxForeclosureData("
            f"id={self.id}, "
            f"lot_size={self.lot_size}, "
            f"assessed_value={self.assessed_value}, "
            f"delinquent={self.delinquent}, "
            f"zoning_code={self.zoning_code}, "
            f"has_water={self.has_water}, "
            f"has_electric={self.has_electric}, "
            f"has_sewage={self.has_sewage}, "
            f"legal_description={self.legal_description}, "
            f"structure={self.structure}, "
            f"year_built={self.year_built}, "
            f"condition={self.condition}, "
            f"occupancy={self.occupancy}, "
            f"street={self.street}, "
            f"city={self.city}, "
            f"state={self.state}, "
            f"zip={self.zip}, "
            f"geometry={self.geometry}, "
            f"date_last_updated={self.date_last_updated})>"
        )

class TaxForeclosureHistory(db.Model):
    id = db.Column(db.String(80), primary_key=True)
    case_number = db.Column(db.String(80), unique=False, nullable=False)

    old_highest_bid = db.Column(db.Float, unique=False, nullable=True)
    new_highest_bid = db.Column(db.Float, unique=False, nullable=True)

    old_status = db.Column(db.String(80), unique=False, nullable=True)
    new_status = db.Column(db.String(80), unique=False, nullable=True)

    old_data = db.Column(db.Text, unique=False, nullable=True)
    new_data = db.Column(db.Text, unique=False, nullable=True)

    date_last_updated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    tags = db.Column(JSON, nullable=True)

    def __repr__(self):
        return (
            f"<TaxForeclosureHistory(id={self.id}, case_number={self.case_number}, old_highest_bid={self.old_highest_bid},"
            f" new_highest_bid={self.new_highest_bid}, old_status={self.old_status}, new_status={self.new_status}, old_data={self.old_data}, new_data={self.new_data} date_last_updated={self.date_last_updated}, tags={self.tags})> )>")


class County(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(255), nullable=False)
    arkgis_url = db.Column(db.String(255), nullable=True)
    eportal_status = db.Column(db.Boolean, nullable=False, default=False)
    associated_towns = db.Column(ARRAY(db.String), nullable=True)

    @classmethod
    def load_county_data(cls):
        county_manager = CountyManager()
        count_data = county_manager.load_county_data()

        for county in count_data:
            # Convert eportal_status to boolean
            if county['Eportal Status'] == "TRUE":
                eportal_status = True
            else:
                eportal_status = False

            # Create a new County instance
            new_county = cls(
                name=county['Name'],
                code=county['Code'],
                arkgis_url=county['Arkgis URL'] + '/query',
                eportal_status=eportal_status,
                associated_towns=county['Associated Towns'] or []  # Default to an empty list if no towns
            )

            # Add the new County object to the session
            db.session.add(new_county)

        # Commit the session to save all the added counties to the database
        db.session.commit()

        print("County data has been successfully added to the database.")

    def __repr__(self):
        return f"<County(id={self.id}, name={self.name}, code={self.code}, associated_towns={self.associated_towns})>"


class AdminUser(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def create_admin(cls):
        """Create the default admin user with a securely hashed password."""
        password = "P@ssw0rd!X9gT7vM"  # Default password
        password_hash = generate_password_hash(password)  # Hash the default password
        new_admin = cls(password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()
        print("Default admin user has been successfully added to the database")

    def check_password(self, password):
        """Check if the provided password matches the stored password hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<AdminUser(id={self.id}, password={self.password}, created_at={self.created_at})>"


class EndpointPermission(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    endpoint = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False)

    @classmethod
    def create_permission(cls, endpoint, role):
        """General method to create permission for any endpoint and role."""
        new_permission = cls(endpoint=endpoint, role=role)
        db.session.add(new_permission)
        db.session.commit()
        print(f"Permission for '{role}' on endpoint '{endpoint}' added to the database.")

    @classmethod
    def create_default_permissions(cls):
        """Create predefined permissions for admin role."""
        permissions = [
            {'endpoint': '/api/users/list', 'role': 'admin'},
            {'endpoint': '/api/stripe/customer', 'role': 'admin'},
            {'endpoint': '/api/county_codes/get_by_county', 'role': 'admin'}
        ]

        for permission in permissions:
            new_permission = cls(endpoint=permission['endpoint'], role=permission['role'])
            db.session.add(new_permission)

        db.session.commit()
        print("Default permissions have been successfully added to the database.")

    def __repr__(self):
        return f"<EndpointPermission(id={self.id}, endpoint={self.endpoint}, permission={self.permission}, created_at={self.created_at})>"


class DeveloperTokenSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DeveloperToken
        include_fk = True


class DeveloperAccountSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DeveloperAccount
        include_fk = True

    # Nest the DeveloperTokenSchema
    developer_tokens = fields.Nested(DeveloperTokenSchema, many=True)


class UserPurchaseStatusSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UserPurchaseStatus
        include_fk = True


class PaymentAccountSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = PaymentAccount
        include_fk = True

    user_purchase_statuses = fields.Nested(UserPurchaseStatusSchema, many=True)


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True  # Include foreign keys in the serialization
        exclude = ('password', 'admin_password')  # Exclude sensitive fields

    # Nest the DeveloperAccountSchema
    developer_account = fields.Nested(DeveloperAccountSchema, many=False)

    # Nest the PaymentAccountSchema
    payment_account = fields.Nested(PaymentAccountSchema, many=False)

class AdditionalTaxForeclosureDataSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = AdditionalTaxForeclosureData
        include_fk = True


class TaxForeclosureSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = TaxForeclosure
        include_fk = True
        exclude = ('spider',)  # Exclude sensitive fields

    additional_data = fields.Nested(AdditionalTaxForeclosureDataSchema, many=False)


class TaxForeclosureHistorySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = TaxForeclosureHistory
        include_fk = True


class CountySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = County
        include_fk = True


class EndpointPermissionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EndpointPermission
        include_fk = True


class AdminUserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = AdminUser
        include_fk = True
        exclude = ('password_hash',)  # Exclude sensitive fields


def create_database():
    """Create the database and populate it with default data."""
    db.drop_all()
    db.create_all()

    # Create default permissions
    EndpointPermission.create_default_permissions()
    # Create the default admin user
    AdminUser.create_admin()
    # Load county data
    County.load_county_data()


if __name__ == "__main__":
    with app.app_context():
        create_database()
